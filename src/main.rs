// Copyright (C) 2019 Soner Tari <sonertari@gmail.com>
//
// This file is part of TestProxy.
//
// TestProxy is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// TestProxy is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with TestProxy.  If not, see <http://www.gnu.org/licenses/>.

extern crate chrono;
extern crate colored;
extern crate core;
extern crate fern;
#[macro_use]
extern crate log;
extern crate openssl;
extern crate regex;
extern crate serde;
extern crate serde_json;
extern crate structopt;
extern crate time;

use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::fs::File;
use std::io::{Error, Read, Write};
use std::io::BufReader;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use chrono::NaiveDateTime;
use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::ec::{EcKey, EcKeyRef};
use openssl::nid::Nid;
use openssl::pkey::Params;
use openssl::ssl::{HandshakeError, NameType, ShutdownState, SslAcceptor, SslConnector, SslFiletype, SslMethod, SslOptions, SslStream, SslVerifyMode, SslVersion};
use regex::Regex;
use serde::{de, Deserialize, Deserializer};
use serde_json::Value;
use structopt::StructOpt;

use crate::config::Config;

mod config;
mod logging;

const CHANNEL_TIMEOUT: Duration = Duration::from_millis(10);

// Default TCP timeouts in millis
const CONNECT_TIMEOUT: u64 = 1000;
// Very short read/write timeouts may break SSL handshake, use values > 10
const READ_TIMEOUT: u64 = 100;
const WRITE_TIMEOUT: u64 = 100;

const WAIT_STREAM_CONNECT: Duration = Duration::from_millis(10);
const MAX_STREAM_CONNECT_TRIALS: i32 = 100;

// For TCP disconnect detection
const MAX_RECV_DISCONNECT_DETECT: i32 = 4;

const MAX_RECV_TRIALS: i32 = MAX_RECV_DISCONNECT_DETECT + 1;

const MAX_CONNECT_TIMEOUT_TRIALS: i32 = MAX_RECV_TRIALS * 20;

// Command exec loops time out after MAX_CMD_TRIALS * read_timeout millis (we loop receiving only)
const MAX_CMD_TRIALS: i32 = MAX_CONNECT_TIMEOUT_TRIALS * 10;

const MAX_TEST_TRIALS: i32 = MAX_CONNECT_TIMEOUT_TRIALS * 10;

const BUF_SIZE: usize = 16384;

type Assertion = BTreeMap<String, Vec<String>>;

#[derive(Deserialize, Debug)]
struct TestState {
    testend: TestEnd,
    cmd: Command,
    payload: String,
    assert: BTreeMap<String, Assertion>,
}

#[derive(Deserialize, Debug)]
struct Test {
    comment: String,
    config: TestConfig,
    states: BTreeMap<i32, BTreeMap<String, String>>,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
enum Proto {
    Tcp,
    Ssl,
}

impl Display for Proto {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        match self {
            Proto::Tcp => write!(fmt, "TCP"),
            Proto::Ssl => write!(fmt, "SSL"),
        }
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
struct ProtoConfig {
    proto: Proto,
    connect_timeout: u64,
    read_timeout: u64,
    write_timeout: u64,
    ip_ttl: u32,
    tcp_nodelay: bool,
    crt: String,
    key: String,
    verify_peer: bool,
    use_sni: bool,
    verify_hostname: bool,
    ciphers: String,
    min_proto_version: String,
    max_proto_version: String,
    no_ssl2: bool,
    no_ssl3: bool,
    no_tls10: bool,
    no_tls11: bool,
    no_tls12: bool,
    no_tls13: bool,
    compression: bool,
    ecdhcurve: String,
}

#[derive(Deserialize, Debug)]
struct TestConfig {
    proto: BTreeMap<String, String>,
    client: BTreeMap<String, String>,
    server: BTreeMap<String, String>,
}

#[derive(Deserialize, Debug)]
struct TestSet {
    comment: String,
    configs: BTreeMap<i32, TestConfig>,
    tests: BTreeMap<i32, Value>,
}

#[derive(Deserialize, Debug)]
struct TestHarness {
    comment: String,
    testsets: BTreeMap<i32, String>,
}

#[derive(Deserialize, Debug)]
struct TestHarnesses {
    comment: String,
    testharnesses: BTreeMap<i32, TestHarness>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TestEnd {
    Server,
    Client,
    None,
}

impl Display for TestEnd {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        match self {
            TestEnd::Server => write!(fmt, "server"),
            TestEnd::Client => write!(fmt, "client"),
            TestEnd::None => write!(fmt, "none"),
        }
    }
}

impl FromStr for TestEnd {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "server" => Ok(TestEnd::Server),
            "client" => Ok(TestEnd::Client),
            testend => {
                error!("Testend not supported: {}", testend);
                panic!("Testend not supported")
            }
        }
    }
}

impl<'de> Deserialize<'de> for TestEnd {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
    {
        // TODO: Use deserializer.is_human_readable()?
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    Send,
    Recv,
    SslConnectFail,
    Timeout,
    Quit,
    Fail,
    None,
}

impl Display for Command {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        match self {
            Command::Send => write!(fmt, "send"),
            Command::Recv => write!(fmt, "recv"),
            Command::SslConnectFail => write!(fmt, "sslconnectfail"),
            Command::Timeout => write!(fmt, "timeout"),
            Command::Quit => write!(fmt, "quit"),
            Command::Fail => write!(fmt, "fail"),
            Command::None => write!(fmt, "none"),
        }
    }
}

impl FromStr for Command {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "send" => Ok(Command::Send),
            "recv" => Ok(Command::Recv),
            "sslconnectfail" => Ok(Command::SslConnectFail),
            "timeout" => Ok(Command::Timeout),
            cmd => {
                error!("Command not supported: {}", cmd);
                panic!("Command not supported")
            }
        }
    }
}

impl<'de> Deserialize<'de> for Command {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

enum SendCommandResult {
    Success,
    TestFinished,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RecvMsgResult {
    SendCommand,
    Quit,
    None,
}

struct Msg {
    cmd: Command,
    payload: String,
    assert: BTreeMap<String, Assertion>,
}

impl Msg {
    fn new(cmd: Command, payload: String, assert: BTreeMap<String, Assertion>) -> Self {
        Msg { cmd, payload, assert }
    }

    fn from_cmd(cmd: Command) -> Self {
        Msg { cmd, payload: "".to_string(), assert: BTreeMap::new() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CmdExecResult {
    Quit,
    Fail,
    Disconnect,
}

fn main() {
    openssl::init();
    openssl_probe::init_ssl_cert_env_vars();

    let config = Config::from_args();

    logging::configure_logging(&config);
    debug!("{:?}", config);

    let file = File::open(config.clone().testharness.unwrap()).unwrap();
    let reader = BufReader::new(file);
    let testharnesses: TestHarnesses = serde_json::from_reader(reader).unwrap();

    warn!("{}", testharnesses.comment);

    for (hid, testharness) in testharnesses.testharnesses {
        warn!("Start test harness {}: {}", hid, testharness.comment);

        let mut thread_handles = Vec::new();
        for (sid, testset_file) in testharness.testsets {
            debug!("Spawn manager for test set {}", sid);

            let file = File::open(testset_file).unwrap();
            let reader = BufReader::new(file);
            let testset: TestSet = serde_json::from_reader(reader).unwrap();

            thread_handles.push(thread::spawn(move || Manager::new(hid, sid).run(testset)));
        }

        for t in thread_handles {
            t.join().unwrap();
        }
    }
    std::process::exit(0);
}

struct Manager {
    hid: i32,
    sid: i32,
    name: String,
    state: usize,
    testend: TestEnd,
    cmd: Command,
    payload: String,
    assert: BTreeMap<String, Assertion>,
    teststates: BTreeMap<i32, TestState>,
    teststate_ids: BTreeMap<i32, i32>,
    test_failed: bool,
    mgr2cli_tx: Sender<Msg>,
    mgr2cli_rx: Arc<Mutex<Receiver<Msg>>>,
    cli2mgr_tx: Sender<Msg>,
    cli2mgr_rx: Receiver<Msg>,
    mgr2srv_tx: Sender<Msg>,
    mgr2srv_rx: Arc<Mutex<Receiver<Msg>>>,
    srv2mgr_tx: Sender<Msg>,
    srv2mgr_rx: Receiver<Msg>,
}

impl Manager {
    fn new(hid: i32, sid: i32) -> Self {
        let (cli2mgr_tx, cli2mgr_rx) = mpsc::channel();
        let (srv2mgr_tx, srv2mgr_rx) = mpsc::channel();

        // ATTENTION: Init these channels in this new() method, and use Arc/Mutex
        // Otherwise, Server/Manager threads do not return, hence join() call gets stuck sometimes
        // TODO: Check why Server/Manager threads do not join() if these channels are init in run() and without Arc/Mutex
        // Use Arc/Mutex to pass receivers to server and client threads
        // We create these channels here for initialization purposes only
        let (mgr2cli_tx, mgr2cli_rx) = mpsc::channel();
        let mgr2cli_rx = Arc::new(Mutex::new(mgr2cli_rx));

        let (mgr2srv_tx, mgr2srv_rx) = mpsc::channel();
        let mgr2srv_rx = Arc::new(Mutex::new(mgr2srv_rx));

        Manager {
            hid,
            sid,
            name: format!("MGR.h{}.s{}.c0", hid, sid),
            state: 1,
            testend: TestEnd::None,
            cmd: Command::None,
            payload: "".to_string(),
            assert: BTreeMap::new(),
            teststates: BTreeMap::new(),
            teststate_ids: BTreeMap::new(),
            test_failed: false,
            mgr2cli_tx,
            mgr2cli_rx,
            cli2mgr_tx,
            cli2mgr_rx,
            mgr2srv_tx,
            mgr2srv_rx,
            srv2mgr_tx,
            srv2mgr_rx,
        }
    }

    fn name(&self, cid: i32) -> String {
        format!("MGR.h{}.s{}.c{}", self.hid, self.sid, cid)
    }

    fn configure_proto(&self, testconfig: &TestConfig) -> ProtoConfig {
        let mut proto = Proto::Tcp;

        let mut connect_timeout = CONNECT_TIMEOUT;
        if testconfig.proto.contains_key("connect_timeout") {
            connect_timeout = testconfig.proto["connect_timeout"].parse().expect("Cannot parse connect_timeout");
        }

        let mut read_timeout = READ_TIMEOUT;
        if testconfig.proto.contains_key("read_timeout") {
            read_timeout = testconfig.proto["read_timeout"].parse().expect("Cannot parse read_timeout");
        }

        let mut write_timeout = WRITE_TIMEOUT;
        if testconfig.proto.contains_key("write_timeout") {
            write_timeout = testconfig.proto["write_timeout"].parse().expect("Cannot parse write_timeout");
        }

        let mut ip_ttl = 15;
        if testconfig.proto.contains_key("ip_ttl") {
            ip_ttl = testconfig.proto["ip_ttl"].parse().expect("Cannot parse ip_ttl");
        }

        let mut tcp_nodelay = true;
        if testconfig.proto.contains_key("tcp_nodelay") {
            tcp_nodelay = testconfig.proto["tcp_nodelay"].eq("yes");
        }

        let mut crt = "".to_string();
        let mut key = "".to_string();
        let mut verify_peer = false;
        let mut use_sni = false;
        let mut verify_hostname = false;
        let mut ciphers = "ALL:-aNULL".to_string();
        let mut min_proto_version = "ssl3".to_string();
        let mut max_proto_version = "tls13".to_string();
        let mut no_ssl2 = false;
        let mut no_ssl3 = false;
        let mut no_tls10 = false;
        let mut no_tls11 = false;
        let mut no_tls12 = false;
        let mut no_tls13 = false;
        let mut compression = false;
        // TODO: Check why no other ecdh curve works
        let mut ecdhcurve = "prime256v1".to_string();

        if testconfig.proto.contains_key("proto") && testconfig.proto["proto"].eq("ssl") {
            proto = Proto::Ssl;

            if testconfig.proto.contains_key("crt") {
                crt = testconfig.proto["crt"].clone();
            }
            if testconfig.proto.contains_key("key") {
                key = testconfig.proto["key"].clone();
            }
            if testconfig.proto.contains_key("verify_peer") {
                verify_peer = testconfig.proto["verify_peer"].eq("yes");
            }
            if testconfig.proto.contains_key("use_sni") {
                use_sni = testconfig.proto["use_sni"].eq("yes");
            }
            if testconfig.proto.contains_key("verify_hostname") {
                verify_hostname = testconfig.proto["verify_hostname"].eq("yes");
            }
            if testconfig.proto.contains_key("ciphers") {
                ciphers = testconfig.proto["ciphers"].clone();
            }
            if testconfig.proto.contains_key("min_proto_version") {
                min_proto_version = testconfig.proto["min_proto_version"].clone();
            }
            if testconfig.proto.contains_key("max_proto_version") {
                max_proto_version = testconfig.proto["max_proto_version"].clone();
            }
            if testconfig.proto.contains_key("no_ssl2") {
                no_ssl2 = testconfig.proto["no_ssl2"].eq("yes");
            }
            if testconfig.proto.contains_key("no_ssl3") {
                no_ssl3 = testconfig.proto["no_ssl3"].eq("yes");
            }
            if testconfig.proto.contains_key("no_tls10") {
                no_tls10 = testconfig.proto["no_tls10"].eq("yes");
            }
            if testconfig.proto.contains_key("no_tls11") {
                no_tls11 = testconfig.proto["no_tls11"].eq("yes");
            }
            if testconfig.proto.contains_key("no_tls12") {
                no_tls12 = testconfig.proto["no_tls12"].eq("yes");
            }
            if testconfig.proto.contains_key("no_tls13") {
                no_tls13 = testconfig.proto["no_tls13"].eq("yes");
            }
            if testconfig.proto.contains_key("compression") {
                compression = testconfig.proto["compression"].eq("yes");
            }
            if testconfig.proto.contains_key("ecdhcurve") {
                ecdhcurve = testconfig.proto["ecdhcurve"].clone();
            }
        }
        ProtoConfig {
            proto,
            connect_timeout,
            read_timeout,
            write_timeout,
            ip_ttl,
            tcp_nodelay,
            crt,
            key,
            verify_peer,
            use_sni,
            verify_hostname,
            ciphers,
            min_proto_version,
            max_proto_version,
            no_ssl2,
            no_ssl3,
            no_tls10,
            no_tls11,
            no_tls12,
            no_tls13,
            compression,
            ecdhcurve,
        }
    }

    fn clone_test(&mut self, test: &Value) {
        self.teststates.clear();
        self.teststate_ids.clear();
        self.test_failed = false;

        self.state = 0;
        let mut i = self.state as i32;

        // TODO: Use ref of states, do not clone?
        for (sid, state) in test["states"].as_object().unwrap().iter() {
            let testend = TestEnd::from_str(&state["testend"].as_str().unwrap()).unwrap();
            let cmd = Command::from_str(&state["cmd"].as_str().unwrap()).unwrap();

            let mut payload = "".to_string();
            let mut payload_file = "".to_string();
            // payload_file has precedence over payload, if both exist
            if state.get("payload_file") != None {
                payload_file = state["payload_file"].as_str().unwrap().to_string();
                payload = String::from_utf8_lossy(&fs::read(&payload_file).unwrap()).to_string();
            } else if state.get("payload") != None {
                payload = state["payload"].as_str().unwrap().to_string();
            }

            let mut assert: BTreeMap<String, Assertion> = BTreeMap::new();
            if state.get("assert") != None {
                assert = serde_json::from_value(state["assert"].clone()).unwrap();
            }

            trace!(target: &self.name, "teststate: {}: {}, {}, {}, {} {:?}", sid, testend, cmd, payload, payload_file, assert);

            self.teststates.insert(sid.parse().unwrap(), TestState { testend, cmd, payload, assert });
            self.teststate_ids.insert(i, sid.parse().unwrap());
            i += 1;
        }
    }

    fn send_command(&self, testend: &TestEnd, msg: Msg) {
        match testend {
            TestEnd::Server => self.mgr2srv_tx.send(msg).unwrap(),
            TestEnd::Client => self.mgr2cli_tx.send(msg).unwrap(),
            TestEnd::None => {
                error!(target: &self.name, "Testend not supported: {}", testend);
                panic!("Testend not supported")
            }
        }
    }

    fn send_next_command(&mut self) -> SendCommandResult {
        if self.state < self.teststate_ids.len() {
            let state = &self.teststate_ids[&(self.state as i32)];
            debug!(target: &self.name, "State: {}, test state: {}", self.state, state);

            self.testend = self.teststates[state].testend.clone();
            self.cmd = self.teststates[state].cmd.clone();
            self.payload = self.teststates[state].payload.clone();
            self.assert = self.teststates[state].assert.clone();

            trace!(target: &self.name, "Sending msg: {}, {}, {}, {:?}", &self.testend, &self.cmd, &self.payload, &self.assert);
            self.send_command(&self.testend, Msg::new(self.cmd.clone(), self.payload.clone(), self.assert.clone()));
            self.state += 1;
        } else {
            self.mgr2srv_tx.send(Msg::from_cmd(Command::Quit)).unwrap();
            self.mgr2cli_tx.send(Msg::from_cmd(Command::Quit)).unwrap();
            return SendCommandResult::TestFinished;
        }
        SendCommandResult::Success
    }

    fn recv_msg(&mut self, testend: TestEnd) -> RecvMsgResult {
        let rx;
        match testend {
            TestEnd::Server => rx = &self.srv2mgr_rx,
            TestEnd::Client => rx = &self.cli2mgr_rx,
            TestEnd::None => {
                error!(target: &self.name, "Testend not supported: {}", testend);
                panic!("Testend not supported")
            }
        }

        let result = rx.recv_timeout(CHANNEL_TIMEOUT);
        match result {
            Ok(msg) => {
                debug!(target: &self.name, "Msg from {} ({}): ({}, {})", testend, msg.payload.len(), msg.cmd, msg.payload);
                let mut test_succeeded = false;
                if self.testend.eq(&testend) {
                    if self.cmd.eq(&msg.cmd) {
                        if self.payload.eq(&msg.payload) {
                            debug!(target: &self.name, "Payloads match for {} {}", testend, msg.cmd);
                            test_succeeded = self.assert == msg.assert;
                            if !self.assert.is_empty() {
                                if test_succeeded {
                                    debug!(target: &self.name, "Assertion succeeded for {} {}", testend, msg.cmd);
                                } else {
                                    error!(target: &self.name, "Assertion failed for {} {}", testend, msg.cmd);
                                }
                            }
                        } else {
                            self.test_failed = true;
                            error!(target: &self.name, "Payloads do NOT match for {} {}, expected payload({})= {}, received payload({})= {}",
                                   testend, msg.cmd, self.payload.len(), self.payload, msg.payload.len(), msg.payload);
                        }
                    } else {
                        debug!(target: &self.name, "Commands do NOT match for {}, expected cmd= {}, received cmd= {}, expected payload({})= {}, received payload({})= {}",
                               testend, self.cmd, msg.cmd, self.payload.len(), self.payload, msg.payload.len(), msg.payload);
                    }
                } else {
                    debug!(target: &self.name, "Testends do NOT match, expected testend= {}, received testend= {}, expected cmd= {}, received cmd= {}, expected payload({})= {}, received payload({})= {}",
                           testend, self.testend, self.cmd, msg.cmd, self.payload.len(), self.payload, msg.payload.len(), msg.payload);
                }

                // TODO: Improve this match/if-else code?
                match msg.cmd {
                    Command::Quit => {
                        return RecvMsgResult::Quit;
                    }
                    Command::Fail => {
                        self.test_failed = true;
                        return RecvMsgResult::Quit;
                    }
                    _ => {
                        if !self.test_failed {
                            if test_succeeded {
                                return RecvMsgResult::SendCommand;
                            }
                        }
                        return RecvMsgResult::Quit;
                    }
                }
            }
            Err(e) => {
                trace!(target: &self.name, "Channel error on {}: {}", testend, e.to_string());
            }
        }
        RecvMsgResult::None
    }

    fn run_test(&mut self) {
        if let SendCommandResult::Success = self.send_next_command() {
            let mut test_trials = 0;
            let mut exit = false;
            loop {
                match self.recv_msg(TestEnd::Server) {
                    RecvMsgResult::SendCommand => {
                        if let SendCommandResult::TestFinished = self.send_next_command() {
                            break;
                        }
                        test_trials = 0;
                    }
                    RecvMsgResult::Quit => {
                        self.send_command(&TestEnd::Client, Msg::from_cmd(Command::Quit));
                        exit = true;
                    }
                    RecvMsgResult::None => {}
                }
                match self.recv_msg(TestEnd::Client) {
                    RecvMsgResult::SendCommand => {
                        if let SendCommandResult::TestFinished = self.send_next_command() {
                            break;
                        }
                        test_trials = 0;
                    }
                    RecvMsgResult::Quit => {
                        self.send_command(&TestEnd::Server, Msg::from_cmd(Command::Quit));
                        exit = true;
                    }
                    RecvMsgResult::None => {}
                }

                test_trials += 1;
                trace!(target: &self.name, "Test loop trial {}", test_trials);
                if test_trials > MAX_TEST_TRIALS {
                    error!(target: &self.name, "Test loop timed out");
                    self.test_failed = true;
                    exit = true;
                }

                if exit {
                    // TODO: Consume all messages in the channel and destroy the channel (?)
                    // Consume any last messages in the channel, otherwise mgr thread cannot return
                    self.recv_msg(TestEnd::Server);
                    self.recv_msg(TestEnd::Client);
                    break;
                }
            }
        }
    }

    fn run(&mut self, testset: TestSet) {
        for (&cid, testconfig) in testset.configs.iter() {
            self.name = self.name(cid);

            let proto = self.configure_proto(&testconfig);
            warn!(target: &self.name, "Start test set {} for test config {}: {}", self.sid, cid, testset.comment);

            for (&tid, test) in testset.tests.iter() {
                let mut comment = "";
                if test.get("comment") != None {
                    comment = test["comment"].as_str().unwrap_or("");
                    debug!(target: &self.name, "{}", comment);
                }

                let (cli2mgr_tx, cli2mgr_rx) = mpsc::channel();
                self.cli2mgr_tx = cli2mgr_tx;
                self.cli2mgr_rx = cli2mgr_rx;
                trace!(target: &self.name, "Created new cli2mgr channel");

                let (srv2mgr_tx, srv2mgr_rx) = mpsc::channel();
                self.srv2mgr_tx = srv2mgr_tx;
                self.srv2mgr_rx = srv2mgr_rx;
                trace!(target: &self.name, "Created new srv2mgr channel");

                let (mgr2cli_tx, mgr2cli_rx) = mpsc::channel();
                self.mgr2cli_tx = mgr2cli_tx;
                self.mgr2cli_rx = Arc::new(Mutex::new(mgr2cli_rx));
                trace!(target: &self.name, "Created new mgr2cli channel");

                let (mgr2srv_tx, mgr2srv_rx) = mpsc::channel();
                self.mgr2srv_tx = mgr2srv_tx;
                self.mgr2srv_rx = Arc::new(Mutex::new(mgr2srv_rx));
                trace!(target: &self.name, "Created new mgr2srv channel");

                let mut server = Server::new(self.hid, self.sid, cid, tid, self.srv2mgr_tx.clone(), Arc::clone(&self.mgr2srv_rx),
                                             proto.clone(), testconfig.server.clone());

                let server_thread = thread::spawn(move || server.run());
                debug!(target: &self.name, "Spawned server for test {}", tid);

                let mut client = Client::new(self.hid, self.sid, cid, tid, self.cli2mgr_tx.clone(), Arc::clone(&self.mgr2cli_rx),
                                             proto.clone(), testconfig.client.clone());

                let client_thread = thread::spawn(move || client.run());
                debug!(target: &self.name, "Spawned client for test {}", tid);

                self.clone_test(test);

                self.run_test();

                if let Ok(rv) = server_thread.join() {
                    self.test_failed |= rv;
                }
                if let Ok(rv) = client_thread.join() {
                    self.test_failed |= rv;
                }

                if !self.test_failed && self.state == self.teststate_ids.len() {
                    info!(target: &self.name, "Test {} succeeded: {}", tid, comment);
                } else {
                    error!(target: &self.name, "Test {} failed: {}", tid, comment);
                    break;
                }
            }

            if self.test_failed {
                break;
            }
        }
        debug!(target: &self.name, "Exit");
    }
}

struct Server {
    hid: i32,
    sid: i32,
    cid: i32,
    tid: i32,
    base: TestEndBase,
}

impl Server {
    fn new(hid: i32, sid: i32, cid: i32, tid: i32, srv2mgr_tx: Sender<Msg>, mgr2srv_rx: Arc<Mutex<mpsc::Receiver<Msg>>>, proto: ProtoConfig, config: BTreeMap<String, String>) -> Self {
        let mut server = Server {
            hid,
            sid,
            cid,
            tid,
            base: TestEndBase::new("".to_string(), srv2mgr_tx, mgr2srv_rx, proto, config),
        };
        server.base.name = server.name(0);
        server
    }

    fn name(&self, stream_id: i32) -> String {
        format!("SRV.h{}.s{}.c{}.t{}.{}", self.hid, self.sid, self.cid, self.tid, stream_id)
    }

    fn run_tcp(&mut self, tcp_stream: &TcpStream, failed: &mut bool) -> bool {
        self.base.cmd_trials = 0;
        loop {
            if let Err(RecvTimeoutError::Disconnected) = self.base.get_command() {
                break false;
            }

            if self.base.cmd == Command::None {
                self.base.cmd_trials += 1;
                trace!(target: &self.base.name, "TCP stream loop cmd trial {}", self.base.cmd_trials);
                if self.base.cmd_trials > MAX_CMD_TRIALS {
                    error!(target: &self.base.name, "TCP stream loop timed out");
                    *failed = true;
                    break true;
                }
            }

            if let Err(e) = self.base.execute_tcp_command(&tcp_stream) {
                if e == CmdExecResult::Fail {
                    *failed = true;
                } else if e == CmdExecResult::Disconnect {
                    break false;
                }
                break true;
            }
            // TODO: How to determine if TcpStream is closed? Currently, we rely on Ok Result of empty read()
        }
    }

    fn run_ssl(&mut self, tcp_stream: &TcpStream, failed: &mut bool) -> bool {
        let mut exit = false;

        let mut sab = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        if self.base.proto.verify_peer {
            sab.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        } else {
            sab.set_verify(SslVerifyMode::NONE);
        }

        sab.set_certificate_file(&self.base.proto.crt, SslFiletype::PEM).expect("Cannot set crt file");
        sab.set_private_key_file(&self.base.proto.key, SslFiletype::PEM).expect("Cannot set key file");

        sab.set_cipher_list(&self.base.proto.ciphers).expect("Cannot set cipher list");

        sab.set_min_proto_version(Some(str2sslversion(&self.base.proto.min_proto_version))).expect("Cannot set min proto version");
        sab.set_max_proto_version(Some(str2sslversion(&self.base.proto.max_proto_version))).expect("Cannot set max proto version");

        if self.base.proto.no_ssl2 {
            sab.set_options(SslOptions::NO_SSLV2);
        }
        if self.base.proto.no_ssl3 {
            sab.set_options(SslOptions::NO_SSLV3);
        }
        if self.base.proto.no_tls10 {
            sab.set_options(SslOptions::NO_TLSV1);
        }
        if self.base.proto.no_tls11 {
            sab.set_options(SslOptions::NO_TLSV1_1);
        }
        if self.base.proto.no_tls12 {
            sab.set_options(SslOptions::NO_TLSV1_2);
        }
        if self.base.proto.no_tls13 {
            sab.set_options(SslOptions::NO_TLSV1_3);
        }
        if !self.base.proto.compression {
            sab.set_options(SslOptions::NO_COMPRESSION);
        }

        let ecdh = EcKey::from_curve_name(Nid::from_raw(ssl_nid_by_name(&self.base.proto.ecdhcurve))).expect("Cannot create EcKey");
        // TODO: Is this the right way of typecasting to EcKeyRef, the compiler is fine with just &ecdh below, but the editor complains
        sab.set_tmp_ecdh(&ecdh as &EcKeyRef<Params>).expect("Cannot set ecdh");

        let acceptor = sab.build();

        let mut ssl_stream_trials = 0;
        let ssl_stream_result: Result<SslStream<&TcpStream>, HandshakeError<&TcpStream>> = loop {
            match acceptor.accept(tcp_stream) {
                Ok(ssl_stream) => {
                    debug!(target: &self.base.name, "SSL stream connected");
                    break Ok(ssl_stream);
                }
                Err(e) => {
                    ssl_stream_trials += 1;
                    debug!(target: &self.base.name, "SSL stream connect HandshakeError ({}): {}", ssl_stream_trials, e);
                    if ssl_stream_trials >= MAX_STREAM_CONNECT_TRIALS {
                        warn!(target: &self.base.name, "SSL stream connect timed out");
                        *failed = true;
                        break Err(e);
                    }
                    thread::sleep(WAIT_STREAM_CONNECT);
                }
            }
        };

        if let Ok(mut ssl_stream) = ssl_stream_result {
            self.base.cmd_trials = 0;
            exit = loop {
                if let Err(RecvTimeoutError::Disconnected) = self.base.get_command() {
                    break false;
                }

                if self.base.cmd == Command::None {
                    self.base.cmd_trials += 1;
                    trace!(target: &self.base.name, "SSL stream loop cmd trial {}", self.base.cmd_trials);
                    if self.base.cmd_trials > MAX_CMD_TRIALS {
                        error!(target: &self.base.name, "SSL stream loop timed out");
                        *failed = true;
                        break true;
                    }
                }

                if let Err(e) = self.base.execute_ssl_command(&mut ssl_stream) {
                    if e == CmdExecResult::Fail {
                        *failed = true;
                    } else if e == CmdExecResult::Disconnect {
                        break false;
                    }
                    break true;
                }

                let ss = ssl_stream.get_shutdown();
                if ss == ShutdownState::RECEIVED || ss == ShutdownState::SENT {
                    debug!(target: &self.base.name, "SSL stream shuts down");
                    if self.base.cmd == Command::Recv {
                        if let Err(_) = self.base.report_cmd_result(Some(&mut ssl_stream)) {
                            break true;
                        }
                    }
                    break false;
                }
            };
            // Stream shutdown fixes the issue where the server was getting stuck
            if let Err(_) = ssl_stream.shutdown() {
                debug!(target: &self.base.name, "SSL shutdown failed");
            }
        }
        exit
    }

    fn run(&mut self) -> bool {
        let addr = format!("{}:{}", self.base.ip, self.base.port);
        let server = TcpListener::bind(addr.clone()).unwrap();
        debug!(target: &self.base.name, "TCP listener connected to {}", addr);

        let mut stream_id = 1;
        let mut tcp_stream_trials = 0;
        let mut exit = false;
        let mut failed = false;

        // nonblocking is necessary to get the next stream (connection)
        server.set_nonblocking(true).unwrap();

        self.base.cmd_trials = 0;
        for server_result in server.incoming() {
            if exit {
                break;
            }
            match server_result {
                Ok(tcp_stream) => {
                    // Reset the trial count of the outer-most loop on success
                    tcp_stream_trials = 0;
                    self.base.name = self.name(stream_id);
                    stream_id += 1;

                    debug!(target: &self.base.name, "TCP stream connected");

                    if self.base.cmd == Command::Timeout {
                        debug!(target: &self.base.name, "Timeout command failed");
                        self.base.reset_command();
                        failed = true;
                        break;
                    }

                    self.base.configure_tcp_stream(&tcp_stream);

                    if self.base.proto.proto == Proto::Tcp {
                        exit = self.run_tcp(&tcp_stream, &mut failed);
                    } else {
                        exit = self.run_ssl(&tcp_stream, &mut failed);
                    }

                    if let Err(_) = tcp_stream.shutdown(Shutdown::Both) {
                        debug!(target: &self.base.name, "TCP shutdown failed");
                    }
                }
                Err(e) => {
                    tcp_stream_trials += 1;
                    trace!(target: &self.base.name, "TCP stream error ({}): {}", tcp_stream_trials, e.to_string());
                    if self.base.cmd == Command::Timeout {
                        if tcp_stream_trials >= MAX_CONNECT_TIMEOUT_TRIALS {
                            debug!(target: &self.base.name, "Timeout command succeeded");
                            self.base.report_cmd_result(None).unwrap_or(());
                            tcp_stream_trials = 0;
                        }
                    } else if tcp_stream_trials >= MAX_STREAM_CONNECT_TRIALS {
                        error!(target: &self.base.name, "TCP stream connect timed out");
                        failed = true;
                        break;
                    }
                    thread::sleep(WAIT_STREAM_CONNECT);
                }
            }

            if let Err(RecvTimeoutError::Disconnected) = self.base.get_command() {
                break;
            }
            if self.base.cmd == Command::Quit {
                debug!(target: &self.base.name, "Received quit command");
                self.base.reset_command();
                break;
            }

            // Do not timeout, if we are executing a command already
            if self.base.cmd == Command::None {
                self.base.cmd_trials += 1;
                trace!(target: &self.base.name, "Server loop cmd trial {}", self.base.cmd_trials);
                if self.base.cmd_trials > MAX_CMD_TRIALS {
                    error!(target: &self.base.name, "Server loop timed out");
                    failed = true;
                    break;
                }
            }
        }

        if failed {
            self.base.tx.send(Msg::from_cmd(Command::Fail)).unwrap();
        }
        debug!(target: &self.base.name, "Return {}", failed);
        failed
    }
}

struct Client {
    base: TestEndBase,
}

impl Client {
    fn new(hid: i32, sid: i32, cid: i32, tid: i32, cli2mgr_tx: Sender<Msg>, mgr2cli_rx: Arc<Mutex<mpsc::Receiver<Msg>>>, proto: ProtoConfig, config: BTreeMap<String, String>) -> Self {
        Client {
            base: TestEndBase::new(format!("CLI.h{}.s{}.c{}.t{}", hid, sid, cid, tid), cli2mgr_tx, mgr2cli_rx, proto, config),
        }
    }

    fn connect_tcp_stream(&self, failed: &mut bool) -> Result<TcpStream, Error> {
        let addr = format!("{}:{}", self.base.ip, self.base.port).parse().unwrap();

        let mut tcp_stream_trials = 0;
        loop {
            match TcpStream::connect_timeout(&addr, Duration::from_millis(self.base.proto.connect_timeout)) {
                Ok(tcp_stream) => {
                    debug!(target: &self.base.name, "TCP stream connected to {}", addr);
                    break Ok(tcp_stream);
                }
                Err(e) => {
                    tcp_stream_trials += 1;
                    debug!(target: &self.base.name, "TCP stream error ({}): {}", tcp_stream_trials, e);
                    if tcp_stream_trials >= MAX_STREAM_CONNECT_TRIALS {
                        error!(target: &self.base.name, "TCP stream connect timed out");
                        *failed = true;
                        break Err(e);
                    }
                    thread::sleep(WAIT_STREAM_CONNECT);
                }
            }
        }
    }

    fn run_tcp(&mut self, tcp_stream: &TcpStream) -> bool {
        self.base.cmd_trials = 0;
        loop {
            if let Err(RecvTimeoutError::Disconnected) = self.base.get_command() {
                break false;
            }

            if self.base.cmd == Command::None {
                self.base.cmd_trials += 1;
                trace!(target: &self.base.name, "TCP stream loop cmd trial {}", self.base.cmd_trials);
                if self.base.cmd_trials > MAX_CMD_TRIALS {
                    error!(target: &self.base.name, "TCP stream loop timed out");
                    break true;
                }
            }

            if let Err(e) = self.base.execute_tcp_command(&tcp_stream) {
                if e == CmdExecResult::Fail {
                    break true;
                }
                break false;
            }
        }
    }

    fn run_ssl(&mut self, tcp_stream: &TcpStream) -> bool {
        let mut failed = false;

        let mut ssl_stream_trials = 0;
        let mut ssl_stream_result: Result<SslStream<&TcpStream>, ()> = Err(());
        loop {
            if let Err(RecvTimeoutError::Disconnected) = self.base.get_command() {
                break;
            }

            if self.base.cmd == Command::None {
                self.base.cmd_trials += 1;
                trace!(target: &self.base.name, "SSL stream connect loop cmd trial {}", self.base.cmd_trials);
                if self.base.cmd_trials > MAX_CMD_TRIALS {
                    error!(target: &self.base.name, "SSL stream connect loop timed out");
                    failed = true;
                    break;
                }
            }
            if self.base.cmd == Command::Quit {
                debug!(target: &self.base.name, "Received quit command");
                self.base.reset_command();
                break;
            }

            let mut scb = SslConnector::builder(SslMethod::tls()).expect("Cannot create SslConnector");

            if !self.base.proto.crt.is_empty() {
                scb.set_certificate_file(&self.base.proto.crt, SslFiletype::PEM).expect("Cannot set crt file");
            }
            if !self.base.proto.key.is_empty() {
                scb.set_private_key_file(&self.base.proto.key, SslFiletype::PEM).expect("Cannot set key file");
            }

            scb.set_cipher_list(&self.base.proto.ciphers).expect("Cannot set cipher list");

            scb.set_min_proto_version(Some(str2sslversion(&self.base.proto.min_proto_version))).expect("Cannot set min proto version");
            scb.set_max_proto_version(Some(str2sslversion(&self.base.proto.max_proto_version))).expect("Cannot set max proto version");

            if self.base.proto.no_ssl2 {
                scb.set_options(SslOptions::NO_SSLV2);
            }
            if self.base.proto.no_ssl3 {
                scb.set_options(SslOptions::NO_SSLV3);
            }
            if self.base.proto.no_tls10 {
                scb.set_options(SslOptions::NO_TLSV1);
            }
            if self.base.proto.no_tls11 {
                scb.set_options(SslOptions::NO_TLSV1_1);
            }
            if self.base.proto.no_tls12 {
                scb.set_options(SslOptions::NO_TLSV1_2);
            }
            if self.base.proto.no_tls13 {
                scb.set_options(SslOptions::NO_TLSV1_3);
            }
            if !self.base.proto.compression {
                scb.set_options(SslOptions::NO_COMPRESSION);
            }

            let ecdh = EcKey::from_curve_name(Nid::from_raw(ssl_nid_by_name(&self.base.proto.ecdhcurve))).expect("Cannot create EcKey");
            // TODO: Is this the right way of typecasting to EcKeyRef, the compiler is fine with just &ecdh below, but the editor complains
            scb.set_tmp_ecdh(&ecdh as &EcKeyRef<Params>).expect("Cannot set ecdh");

            let mut scc = scb.build().configure().expect("Cannot create SSL ConnectConfiguration");
            if self.base.proto.verify_peer {
                scc.set_verify(SslVerifyMode::PEER);
            } else {
                scc.set_verify(SslVerifyMode::NONE);
            }

            if !self.base.proto.use_sni {
                scc = scc.use_server_name_indication(false);
            }
            if !self.base.proto.verify_hostname {
                scc = scc.verify_hostname(false);
            }

            match scc.connect("localhost", tcp_stream) {
                Ok(ssl_stream) => {
                    debug!(target: &self.base.name, "SSL stream connected");
                    if self.base.cmd == Command::SslConnectFail {
                        debug!(target: &self.base.name, "SslConnectFail command failed");
                        self.base.reset_command();
                        failed = true;
                    } else {
                        ssl_stream_result = Ok(ssl_stream);
                    }
                    break;
                }
                Err(e) => {
                    ssl_stream_trials += 1;
                    debug!(target: &self.base.name, "SSL stream error ({}): {}", ssl_stream_trials, e);
                    if ssl_stream_trials >= MAX_STREAM_CONNECT_TRIALS {
                        ssl_stream_trials = 0;
                        warn!(target: &self.base.name, "SSL stream connect timed out");
                        if self.base.cmd == Command::SslConnectFail {
                            debug!(target: &self.base.name, "SslConnectFail command succeeded");
                            self.base.report_cmd_result(None).unwrap_or(());
                        } else {
                            failed = true;
                            break;
                        }
                    }
                    thread::sleep(WAIT_STREAM_CONNECT);
                }
            }
        };

        if let Ok(mut ssl_stream) = ssl_stream_result {
            self.base.cmd_trials = 0;
            loop {
                if let Err(RecvTimeoutError::Disconnected) = self.base.get_command() {
                    break;
                }

                if self.base.cmd == Command::None {
                    self.base.cmd_trials += 1;
                    trace!(target: &self.base.name, "SSL stream loop cmd trial {}", self.base.cmd_trials);
                    if self.base.cmd_trials > MAX_CMD_TRIALS {
                        error!(target: &self.base.name, "SSL stream loop timed out");
                        failed = true;
                        break;
                    }
                }

                if let Err(e) = self.base.execute_ssl_command(&mut ssl_stream) {
                    if e == CmdExecResult::Fail {
                        failed = true;
                    }
                    break;
                }

                let ss = ssl_stream.get_shutdown();
                if ss == ShutdownState::RECEIVED || ss == ShutdownState::SENT {
                    debug!(target: &self.base.name, "SSL stream shuts down");
                    if self.base.cmd == Command::Recv {
                        if let Err(_) = self.base.report_cmd_result(Some(&mut ssl_stream)) { failed = true; }
                    }
                    break;
                }
            }
            if let Err(_) = ssl_stream.shutdown() {
                debug!(target: &self.base.name, "SSL shutdown failed");
            }
        }
        failed
    }

    fn run(&mut self) -> bool {
        let mut failed = false;

        if let Ok(tcp_stream) = self.connect_tcp_stream(&mut failed) {
            self.base.configure_tcp_stream(&tcp_stream);

            if self.base.proto.proto == Proto::Tcp {
                failed = self.run_tcp(&tcp_stream);
            } else {
                failed = self.run_ssl(&tcp_stream);
            }
            if let Err(_) = tcp_stream.shutdown(Shutdown::Both) {
                debug!(target: &self.base.name, "TCP shutdown failed");
            }
        }

        if failed {
            self.base.tx.send(Msg::from_cmd(Command::Fail)).unwrap();
        }
        debug!(target: &self.base.name, "Return {}", failed);
        failed
    }
}

struct TestEndBase {
    name: String,
    ip: String,
    port: String,
    proto: ProtoConfig,
    tx: Sender<Msg>,
    rx: Arc<Mutex<mpsc::Receiver<Msg>>>,
    cmd: Command,
    payload: String,
    assert: BTreeMap<String, Assertion>,
    recv_payload: String,
    recv_trials: i32,
    cmd_trials: i32,
    disconnect_detect_trials: i32,
}

impl TestEndBase {
    fn new(name: String, tx: Sender<Msg>, rx: Arc<Mutex<mpsc::Receiver<Msg>>>, proto: ProtoConfig, config: BTreeMap<String, String>) -> Self {
        let mut testend = TestEndBase {
            name,
            ip: config["ip"].clone(),
            port: config["port"].clone(),
            proto,
            tx,
            rx,
            cmd: Command::None,
            payload: "".to_string(),
            assert: BTreeMap::new(),
            recv_payload: "".to_string(),
            recv_trials: 0,
            cmd_trials: 0,
            disconnect_detect_trials: 0,
        };
        testend.configure_proto(config);
        testend
    }

    fn configure_proto(&mut self, config: BTreeMap<String, String>) {
        if config.contains_key("proto") {
            if config["proto"].eq("tcp") {
                self.proto.proto = Proto::Tcp;
            } else if config["proto"].eq("ssl") {
                self.proto.proto = Proto::Ssl;
            }
        }

        if config.contains_key("connect_timeout") {
            self.proto.connect_timeout = config["connect_timeout"].parse().expect("Cannot parse connect_timeout");
        }

        if config.contains_key("read_timeout") {
            self.proto.read_timeout = config["read_timeout"].parse().expect("Cannot parse read_timeout");
        }

        if config.contains_key("write_timeout") {
            self.proto.write_timeout = config["write_timeout"].parse().expect("Cannot parse write_timeout");
        }

        if config.contains_key("ip_ttl") {
            self.proto.ip_ttl = config["ip_ttl"].parse().expect("Cannot parse ip_ttl");
        }

        if config.contains_key("tcp_nodelay") {
            self.proto.tcp_nodelay = config["tcp_nodelay"].eq("yes");
        }

        if config.contains_key("crt") {
            self.proto.crt = config["crt"].clone();
        }

        if config.contains_key("key") {
            self.proto.key = config["key"].clone();
        }

        if config.contains_key("verify_peer") {
            self.proto.verify_peer = config["verify_peer"].eq("yes");
        }

        if config.contains_key("use_sni") {
            self.proto.use_sni = config["use_sni"].eq("yes");
        }

        if config.contains_key("verify_hostname") {
            self.proto.verify_hostname = config["verify_hostname"].eq("yes");
        }

        if config.contains_key("ciphers") {
            self.proto.ciphers = config["ciphers"].clone();
        }

        if config.contains_key("min_proto_version") {
            self.proto.min_proto_version = config["min_proto_version"].clone();
        }

        if config.contains_key("max_proto_version") {
            self.proto.max_proto_version = config["max_proto_version"].clone();
        }

        if config.contains_key("no_ssl2") {
            self.proto.no_ssl2 = config["no_ssl2"].eq("yes");
        }

        if config.contains_key("no_ssl3") {
            self.proto.no_ssl3 = config["no_ssl3"].eq("yes");
        }

        if config.contains_key("no_tls10") {
            self.proto.no_tls10 = config["no_tls10"].eq("yes");
        }

        if config.contains_key("no_tls11") {
            self.proto.no_tls11 = config["no_tls11"].eq("yes");
        }

        if config.contains_key("no_tls12") {
            self.proto.no_tls12 = config["no_tls12"].eq("yes");
        }

        if config.contains_key("no_tls13") {
            self.proto.no_tls13 = config["no_tls13"].eq("yes");
        }

        if config.contains_key("compression") {
            self.proto.compression = config["compression"].eq("yes");
        }

        if config.contains_key("ecdhcurve") {
            self.proto.ecdhcurve = config["ecdhcurve"].clone();
        }
    }

    fn configure_tcp_stream(&self, tcp_stream: &TcpStream) {
        tcp_stream.set_read_timeout(Some(Duration::from_millis(self.proto.read_timeout))).expect("Cannot set write_timeout");
        tcp_stream.set_write_timeout(Some(Duration::from_millis(self.proto.write_timeout))).expect("Cannot set write_timeout");
        tcp_stream.set_ttl(self.proto.ip_ttl).expect("Cannot set ip_ttl");
        if self.proto.tcp_nodelay {
            tcp_stream.set_nodelay(true).expect("Cannot disable TCP_NODELAY");
        }
        // Do not set nonblocking to true
        //tcp_stream.set_nonblocking(true).unwrap();
    }

    fn reset_command(&mut self) {
        self.cmd = Command::None;
        self.payload.clear();
        self.assert.clear();
        self.recv_payload.clear();
        self.recv_trials = 0;
        self.cmd_trials = 0;
        self.disconnect_detect_trials = 0;
    }

    fn get_command(&mut self) -> Result<(), RecvTimeoutError> {
        match self.rx.lock().unwrap().recv_timeout(CHANNEL_TIMEOUT) {
            Ok(msg) => {
                self.cmd = msg.cmd;
                self.payload = msg.payload;
                self.assert = msg.assert;
                self.cmd_trials = 0;
                debug!(target: &self.name, "Msg from mgr ({}): ({}, {}, {:?})", self.payload.len(), self.cmd, self.payload, self.assert);
            }
            Err(e) => {
                if e != RecvTimeoutError::Timeout {
                    error!(target: &self.name, "Recv error: {}", e.to_string());
                }
                return Err(e);
            }
        }
        Ok(())
    }

    // TODO: Should all tx's use this function?
    fn report_cmd_result(&mut self, ssl_stream: Option<&mut SslStream<&TcpStream>>) -> Result<(), ()> {
        let mut rv = Ok(());

        if let Some(ssl_stream) = ssl_stream {
            if self.assert_ssl_config(ssl_stream) {
                // Signal assertion failure to mgr by clearing all assertions
                self.assert.clear();
                rv = Err(());
            }
        }

        let payload;
        if self.cmd == Command::Recv {
            if !self.payload.eq(&self.recv_payload) {
                debug!(target: &self.name, "Payloads do NOT match for {}, payload({})= {}, recv_payload({})= {}",
                       self.cmd, self.payload.len(), self.payload, self.recv_payload.len(), self.recv_payload);
                rv = Err(());
            }
            payload = self.recv_payload.clone();
        } else {
            payload = self.payload.clone();
        }

        self.tx.send(Msg::new(self.cmd.clone(), payload, self.assert.clone())).unwrap();
        self.reset_command();
        rv
    }

    fn process_recv_payload(&mut self, ssl_stream: Option<&mut SslStream<&TcpStream>>) -> Result<(), ()> {
        self.recv_trials += 1;
        // ATTENTION: Wait for any extra data even after payload matches exactly, because the proxy should not send anything else
        if (self.payload.starts_with(&self.recv_payload) || self.recv_payload.is_empty()) &&
            self.recv_trials < MAX_RECV_TRIALS {
            trace!(target: &self.name, "Recv trial {} ({}): {}", self.recv_trials, self.recv_payload.len(), self.recv_payload);
            return Ok(());
        }

        trace!(target: &self.name, "Reporting after recv trial {} ({}): {}", self.recv_trials, self.recv_payload.len(), self.recv_payload);
        self.report_cmd_result(ssl_stream)
    }

    // TODO: Can we improve code reuse with execute_tcp_command()?
    fn execute_ssl_command(&mut self, ssl_stream: &mut SslStream<&TcpStream>) -> Result<(), CmdExecResult> {
        match self.cmd {
            Command::Send => {
                // TODO: Is it possible to handle send result similarly to recv? But we can call ssl_write() only once
                match ssl_stream.ssl_write(&self.payload.as_bytes()) {
                    Ok(n) => {
                        if self.payload.len() == n {
                            match ssl_stream.flush() {
                                Ok(()) => {
                                    if let Err(_) = self.report_cmd_result(Some(ssl_stream)) {
                                        return Err(CmdExecResult::Fail);
                                    }
                                    return Ok(());
                                }
                                Err(e) => {
                                    error!(target: &self.name, "SSL stream write flush error: {}", e.to_string());
                                }
                            }
                        } else {
                            error!(target: &self.name, "SSL stream write size does NOT match payload size: ({}, {})", n, self.payload.len());
                        }
                    }
                    Err(e) => {
                        error!(target: &self.name, "SSL stream write error: {}", e.to_string());
                    }
                }
                self.payload = "".to_string();
                self.report_cmd_result(Some(ssl_stream)).unwrap_or(());
                return Err(CmdExecResult::Fail);
            }
            Command::Recv => {
                let mut line = [0; BUF_SIZE];
                // Do not use ssl_read() here, it doesn't accept 0 bytes as received?
                match ssl_stream.ssl_read(&mut line) {
                    Ok(n) => {
                        trace!(target: &self.name, "SSL stream recv_payload: {}", self.recv_trials);
                        self.recv_trials = 0;
                        self.recv_payload.push_str(&String::from_utf8_lossy(&line[0..n]).to_string());
                    }
                    // TODO: Should we handle ErrorCode::ZERO_RETURN and other errors separately?
                    Err(e) => {
                        debug!(target: &self.name, "SSL stream read error: {}", e.to_string());
                    }
                }
                if let Err(_) = self.process_recv_payload(Some(ssl_stream)) {
                    return Err(CmdExecResult::Fail);
                }
            }
            Command::SslConnectFail => {
                debug!(target: &self.name, "Received SslConnectFail command while connected");
                return Err(CmdExecResult::Disconnect);
            }
            Command::Timeout => {
                debug!(target: &self.name, "Received Timeout command while connected");
                return Err(CmdExecResult::Disconnect);
            }
            Command::Quit => {
                self.reset_command();
                return Err(CmdExecResult::Quit);
            }
            Command::Fail => {
                self.reset_command();
                return Err(CmdExecResult::Fail);
            }
            Command::None => {}
        }
        Ok(())
    }

    fn execute_tcp_command(&mut self, mut tcp_stream: &TcpStream) -> Result<(), CmdExecResult> {
        match self.cmd {
            Command::Send => {
                // TODO: Is it possible to handle send result similarly to recv? But we can call ssl_write() only once
                match tcp_stream.write(&self.payload.as_bytes()) {
                    Ok(n) => {
                        if self.payload.len() == n {
                            match tcp_stream.flush() {
                                Ok(()) => {
                                    if let Err(_) = self.report_cmd_result(None) {
                                        return Err(CmdExecResult::Fail);
                                    }
                                    return Ok(());
                                }
                                Err(e) => {
                                    error!(target: &self.name, "TCP stream write flush error: {}", e.to_string());
                                }
                            }
                        } else {
                            error!(target: &self.name, "TCP stream write size does NOT match payload size: ({}, {})", n, self.payload.len());
                        }
                    }
                    Err(e) => {
                        error!(target: &self.name, "TCP stream write error: {}", e.to_string());
                    }
                }
                self.payload = "".to_string();
                self.report_cmd_result(None).unwrap_or(());
                return Err(CmdExecResult::Fail);
            }
            Command::Recv => {
                let mut line = [0; BUF_SIZE];
                // Do not use read_to_string() or read_to_end() here, they don't read anything
                match tcp_stream.read(&mut line) {
                    Ok(n) => {
                        let recv = &String::from_utf8_lossy(&line[0..n]).to_string();
                        trace!(target: &self.name, "TCP stream read OK ({}): {}", recv.len(), recv);
                        if recv.is_empty() {
                            self.disconnect_detect_trials += 1;
                            trace!(target: &self.name, "TCP stream read disconnect detect trial: {}", self.disconnect_detect_trials);
                            if self.disconnect_detect_trials >= MAX_RECV_DISCONNECT_DETECT {
                                debug!(target: &self.name, "TCP stream read DISCONNECT detected");
                                self.recv_payload.push_str(recv);

                                if let Err(_) = self.report_cmd_result(None) {
                                    return Err(CmdExecResult::Fail);
                                }
                                return Err(CmdExecResult::Disconnect);
                            }
                        } else {
                            self.recv_trials = 0;
                            self.disconnect_detect_trials = 0;
                        }
                        self.recv_payload.push_str(recv);
                    }
                    // TODO: Handle WouldBlock and other errors separately?
                    Err(e) => {
                        debug!(target: &self.name, "TCP stream read error: {}", e.to_string());
                    }
                }
                if let Err(_) = self.process_recv_payload(None) {
                    return Err(CmdExecResult::Fail);
                }
            }
            Command::SslConnectFail => {
                debug!(target: &self.name, "Received SslConnectFail command while connected");
                return Err(CmdExecResult::Disconnect);
            }
            Command::Timeout => {
                debug!(target: &self.name, "Received Timeout command while connected");
                return Err(CmdExecResult::Disconnect);
            }
            Command::Quit => {
                self.reset_command();
                return Err(CmdExecResult::Quit);
            }
            Command::Fail => {
                self.reset_command();
                return Err(CmdExecResult::Fail);
            }
            Command::None => {}
        }
        Ok(())
    }

    fn assert_ssl_config(&mut self, ssl_stream: &mut SslStream<&TcpStream>) -> bool {
        if self.assert.is_empty() {
            return false;
        }

        let mut failed = false;

        let ssl = ssl_stream.ssl();
        let cipher = ssl.current_cipher().unwrap();
        debug!(target: &self.name, "SSL stream current_cipher name: {}, standard_name: {}, version: {}, cipher_nid: {:?}", cipher.name(), cipher.standard_name().unwrap(), cipher.version(), cipher.cipher_nid().unwrap());
        debug!(target: &self.name, "SSL stream current_cipher description: {}", cipher.description());
        debug!(target: &self.name, "SSL stream version_str {}", ssl.version_str());
        debug!(target: &self.name, "SSL stream state_string {}", ssl.state_string());
        //debug!(target: &self.name, "SSL stream state_string_long {}", ssl.state_string_long());
        // SNI sent by client
        debug!(target: &self.name, "SSL stream servername {}", ssl.servername(NameType::HOST_NAME).unwrap());
        //debug!(target: &self.name, "SSL stream time: {:#?}, timeout: {:#?}", ssl.session().unwrap().time(), ssl.session().unwrap().timeout());

        match ssl.peer_certificate() {
            Some(peer_cert) => {
                let mut pcv = Vec::new();
                // TODO: Check why all peer.cert entry methods give the same entries
                for e in peer_cert.issuer_name().entries() {
                    pcv.push(format!("{}", &e.data().as_utf8().unwrap()));
                }
                let peer_certificate = pcv.join(", ");
                debug!(target: &self.name, "SSL stream peer_certificate: {}", peer_certificate);
                debug!(target: &self.name, "SSL stream peer_certificate not_before: {}", peer_cert.not_before());
                debug!(target: &self.name, "SSL stream peer_certificate not_after: {}", peer_cert.not_after());
                //debug!(target: &self.name, "SSL stream peer_certificate serial_number: {:#?}", peer_cert.serial_number().to_bn().unwrap());

                if self.assert.contains_key("peer_certificate") {
                    failed |= self.assert_str("peer_certificate", &peer_certificate);
                }
                if self.assert.contains_key("peer_certificate_not_before") {
                    failed |= self.assert_date("peer_certificate_not_before", peer_cert.not_before());
                }
                if self.assert.contains_key("peer_certificate_not_after") {
                    failed |= self.assert_date("peer_certificate_not_after", peer_cert.not_after());
                }
            }
            None => {}
        }

        if self.assert.contains_key("ssl_proto_version") {
            failed |= self.assert_str("ssl_proto_version", ssl.version_str());
        }
        if self.assert.contains_key("current_cipher_name") {
            failed |= self.assert_str("current_cipher_name", cipher.name());
        }
        if self.assert.contains_key("current_cipher_version") {
            failed |= self.assert_str("current_cipher_version", cipher.version());
        }
        if self.assert.contains_key("ssl_state") {
            failed |= self.assert_str("ssl_state", ssl.state_string());
        }
        failed
    }

    fn assert_str(&self, key: &str, value: &str) -> bool {
        let mut rv = false;
        for (o, vs) in self.assert[key].iter() {
            let mut failed = false;
            match o.as_str() {
                "==" => {
                    // Only one match is enough
                    failed = true;
                    for v in vs.iter() {
                        if v == value {
                            failed = false;
                        } else {
                            warn!(target: &self.name, "Assertion failed {} == {}, received: {}", key, v, value);
                        }
                    }
                }
                "!=" => {
                    for v in vs.iter() {
                        if v == value {
                            failed = true;
                            warn!(target: &self.name, "Assertion failed {} != {}, received: {}", key, v, value);
                        }
                    }
                }
                "match" => {
                    for v in vs.iter() {
                        if !Regex::new(v).unwrap().is_match(value) {
                            failed = true;
                            warn!(target: &self.name, "Assertion failed {} match {}, received: {}", key, v, value);
                        }
                    }
                }
                "!match" => {
                    for v in vs.iter() {
                        if Regex::new(v).unwrap().is_match(value) {
                            failed = true;
                            warn!(target: &self.name, "Assertion failed {} !match {}, received: {}", key, v, value);
                        }
                    }
                }
                _ => {}
            }
            if failed {
                error!(target: &self.name, "Assertion failed {}, received: {}", key, value);
                rv = true;
            }
        }
        rv
    }

    fn assert_date(&self, key: &str, value: &Asn1TimeRef) -> bool {
        let mut rv = false;

        let value = NaiveDateTime::parse_from_str(&value.to_string(), "%b %d %H:%M:%S %Y GMT").unwrap();

        let now: &Asn1TimeRef = &Asn1Time::days_from_now(0).unwrap() as &Asn1TimeRef;
        let now = NaiveDateTime::parse_from_str(&now.to_string(), "%b %d %H:%M:%S %Y GMT").unwrap();

        for (o, vs) in self.assert[key].iter() {
            let mut failed = false;
            match o.as_str() {
                ">=" => {
                    for v in vs.iter() {
                        // v can be negative
                        let now_plus_days = now.checked_add_signed(time::Duration::days(v.parse().unwrap())).unwrap();
                        if value < now_plus_days {
                            failed = true;
                            warn!(target: &self.name, "Assertion failed {} >= {}, received: {}", key, now_plus_days, value);
                        }
                    }
                }
                "<=" => {
                    for v in vs.iter() {
                        let now_plus_days = now.checked_add_signed(time::Duration::days(v.parse().unwrap())).unwrap();
                        if value > now_plus_days {
                            failed = true;
                            warn!(target: &self.name, "Assertion failed {} <= {}, received: {}", key, now_plus_days, value);
                        }
                    }
                }
                _ => {}
            }
            if failed {
                error!(target: &self.name, "Assertion failed {}, received: {}", key, value);
                rv = true;
            }
        }
        rv
    }
}

fn str2sslversion(s: &str) -> SslVersion {
    match s {
        "ssl3" => { SslVersion::SSL3 }
        "tls10" => { SslVersion::TLS1 }
        "tls11" => { SslVersion::TLS1_1 }
        "tls12" => { SslVersion::TLS1_2 }
        "tls13" => { SslVersion::TLS1_3 }
        _ => { SslVersion::TLS1_2 } // XXX?
    }
}

// TODO: Rust openssl lib does not have OBJ_sn2nid() equivalent, what is the best way to find nid by name?
fn ssl_nid_by_name(s: &str) -> i32 {
    let mut nid = 0; // UNDEF
    for i in 0..1200 {
        match Nid::from_raw(i).short_name() {
            Ok(n) => {
                if n == s {
                    trace!("Found nid {} = {}", i, n);
                    nid = i;
                    break;
                }
                //trace!("Nid {} = {}", i, n);
            }
            Err(_) => {
                //trace!("Undefined nid {}", i);
            }
        }
    }
    nid
}