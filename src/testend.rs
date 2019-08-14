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

use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::mpsc;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::mpsc::Sender;
use std::sync::Mutex;
use std::time::Duration;

use chrono::NaiveDateTime;
use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::nid::Nid;
use openssl::ssl::{NameType, SslStream, SslVersion};
use regex::Regex;
use serde::{de, Deserialize, Deserializer};
use serde_json::Value;

pub const CHANNEL_TIMEOUT: Duration = Duration::from_millis(10);

// Default TCP timeouts in millis
pub const CONNECT_TIMEOUT: u64 = 1000;
// Very short read/write timeouts may break SSL handshake,
// otherwise read/write operations may be timed out before finished (?).
// For example, it is hard to find the correct WRITE_TIMEOUT,
// WRITE_TIMEOUT should actually be computed based on the size of write data (?).
pub const READ_TIMEOUT: u64 = CONNECT_TIMEOUT / 5;
pub const WRITE_TIMEOUT: u64 = CONNECT_TIMEOUT / 5;

pub const WAIT_STREAM_CONNECT: Duration = Duration::from_millis(CONNECT_TIMEOUT / 100);
pub const MAX_STREAM_CONNECT_TRIALS: i32 = 10;

// For TCP disconnect detection
const MAX_RECV_DISCONNECT_DETECT: i32 = 4;

const MAX_RECV_TRIALS: i32 = MAX_RECV_DISCONNECT_DETECT + 1;

pub const MAX_CONNECT_TIMEOUT_TRIALS: i32 = MAX_RECV_TRIALS * 20;

// Command exec loops time out after MAX_CMD_TRIALS * read_timeout millis (we loop receiving only)
pub const MAX_CMD_TRIALS: i32 = MAX_CONNECT_TIMEOUT_TRIALS * 10;

pub const MAX_TEST_TRIALS: i32 = MAX_CONNECT_TIMEOUT_TRIALS * 10;

const BUF_SIZE: usize = 16384;

pub type Assertion = BTreeMap<String, Vec<String>>;

#[derive(Deserialize, Debug)]
pub struct TestState {
    pub testend: TestEnd,
    pub cmd: Command,
    pub payload: String,
    pub assert: BTreeMap<String, Assertion>,
}

#[derive(Deserialize, Debug)]
struct Test {
    comment: String,
    config: TestConfig,
    states: BTreeMap<i32, BTreeMap<String, String>>,
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Proto {
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

impl FromStr for Proto {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(Proto::Tcp),
            "ssl" => Ok(Proto::Ssl),
            proto => {
                error!("Proto not supported: {}", proto);
                panic!("Proto not supported")
            }
        }
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ProtoConfig {
    pub proto: Proto,
    pub connect_timeout: u64,
    pub read_timeout: u64,
    pub write_timeout: u64,
    pub ip_ttl: u32,
    pub tcp_nodelay: bool,
    pub crt: String,
    pub key: String,
    pub verify_peer: bool,
    pub use_sni: bool,
    pub sni_servername: String,
    pub verify_hostname: bool,
    pub ciphers: String,
    pub min_proto_version: String,
    pub max_proto_version: String,
    pub no_ssl2: bool,
    pub no_ssl3: bool,
    pub no_tls10: bool,
    pub no_tls11: bool,
    pub no_tls12: bool,
    pub no_tls13: bool,
    pub compression: bool,
    pub ecdhcurve: String,
    // Whether to set ecdh curve or not, it is expensive to find its name by nid
    pub set_ecdhcurve: bool,
}

#[derive(Deserialize, Debug)]
pub struct TestConfig {
    pub proto: BTreeMap<String, String>,
    pub client: BTreeMap<String, String>,
    pub server: BTreeMap<String, String>,
}

#[derive(Deserialize, Debug)]
pub struct TestSet {
    pub comment: String,
    pub configs: BTreeMap<i32, TestConfig>,
    pub tests: BTreeMap<i32, Value>,
}

#[derive(Deserialize, Debug)]
pub struct TestHarness {
    pub comment: String,
    pub testsets: BTreeMap<i32, String>,
}

#[derive(Deserialize, Debug)]
pub struct TestHarnesses {
    pub comment: String,
    pub testharnesses: BTreeMap<i32, TestHarness>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestEnd {
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
pub enum Command {
    Send,
    Recv,
    SslConnectFail,
    Timeout,
    Quit,
    Fail,
    KeepAlive,
    None,
}

impl Command {
    pub fn is_action_command(&self) -> bool {
        match self {
            Command::Send => true,
            Command::Recv => true,
            Command::SslConnectFail => true,
            Command::Timeout => true,
            Command::Quit => false,
            Command::Fail => false,
            Command::KeepAlive => false,
            Command::None => false,
        }
    }
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
            Command::KeepAlive => write!(fmt, "keepalive"),
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

pub enum SendCommandResult {
    Success,
    TestFinished,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecvMsgResult {
    SendCommand,
    Quit,
    NoMsg,
}

pub struct Msg {
    pub cmd: Command,
    pub payload: String,
    pub assert: BTreeMap<String, Assertion>,
}

impl Msg {
    pub fn new(cmd: Command, payload: String, assert: BTreeMap<String, Assertion>) -> Self {
        Msg { cmd, payload, assert }
    }

    pub fn from_cmd(cmd: Command) -> Self {
        Msg { cmd, payload: "".to_string(), assert: BTreeMap::new() }
    }
}

type CommandResult = Result<(), CommandError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandError {
    Quit,
    Fail,
    Disconnect,
}

pub struct TestEndBase {
    pub name: String,
    pub ip: String,
    pub port: String,
    pub proto: ProtoConfig,
    pub tx: Sender<Msg>,
    rx: Arc<Mutex<mpsc::Receiver<Msg>>>,
    pub cmd: Command,
    payload: String,
    assert: BTreeMap<String, Assertion>,
    recv_payload: String,
    recv_trials: i32,
    pub cmd_trials: i32,
    disconnect_detect_trials: i32,
}

impl TestEndBase {
    pub fn new(name: String, tx: Sender<Msg>, rx: Arc<Mutex<mpsc::Receiver<Msg>>>, proto: ProtoConfig, config: BTreeMap<String, String>) -> Self {
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
            self.proto.proto = Proto::from_str(config["proto"].as_str()).unwrap();
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

        if config.contains_key("sni_servername") {
            self.proto.sni_servername = config["sni_servername"].clone();
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
            self.proto.set_ecdhcurve = true;
        }
    }

    pub fn configure_tcp_stream(&self, tcp_stream: &TcpStream) {
        tcp_stream.set_read_timeout(Some(Duration::from_millis(self.proto.read_timeout))).expect("Cannot set write_timeout");
        tcp_stream.set_write_timeout(Some(Duration::from_millis(self.proto.write_timeout))).expect("Cannot set write_timeout");
        tcp_stream.set_ttl(self.proto.ip_ttl).expect("Cannot set ip_ttl");
        if self.proto.tcp_nodelay {
            tcp_stream.set_nodelay(true).expect("Cannot disable TCP_NODELAY");
        }
        // Do not set nonblocking to true
        //tcp_stream.set_nonblocking(true).unwrap();
    }

    pub fn reset_command(&mut self) {
        self.cmd = Command::None;
        self.payload.clear();
        self.assert.clear();
        self.recv_payload.clear();
        self.recv_trials = 0;
        self.cmd_trials = 0;
        self.disconnect_detect_trials = 0;
    }

    pub fn get_command(&mut self) -> Result<(), RecvTimeoutError> {
        match self.rx.lock().unwrap().recv_timeout(CHANNEL_TIMEOUT) {
            Ok(msg) => {
                if msg.cmd == Command::KeepAlive && self.cmd != Command::None {
                    error!(target: &self.name, "Received KeepAlive command while executing cmd: {}", self.cmd);
                }
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
    pub fn report_cmd_result(&mut self, ssl_stream: Option<&mut SslStream<&TcpStream>>) -> Result<(), ()> {
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

    pub fn check_command_timeout(&mut self) -> CommandResult {
        self.cmd_trials += 1;
        trace!(target: &self.name, "Command loop {}", self.cmd_trials);
        if self.cmd_trials > MAX_CMD_TRIALS {
            error!(target: &self.name, "Command loop timed out");
            return Err(CommandError::Fail);
        }
        Ok(())
    }

    // TODO: Can we improve code reuse with execute_tcp_command()?
    pub fn execute_ssl_command(&mut self, ssl_stream: &mut SslStream<&TcpStream>) -> CommandResult {
        match self.cmd {
            Command::Send => {
                // TODO: Is it possible to handle send result similarly to recv? But we can call ssl_write() only once
                match ssl_stream.ssl_write(&self.payload.as_bytes()) {
                    Ok(n) => {
                        if self.payload.len() == n {
                            match ssl_stream.flush() {
                                Ok(()) => {
                                    if let Err(_) = self.report_cmd_result(Some(ssl_stream)) {
                                        return Err(CommandError::Fail);
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
                return Err(CommandError::Fail);
            }
            Command::Recv => {
                let mut line = [0; BUF_SIZE];
                // Do not use ssl_read() here, it doesn't accept 0 bytes as received?
                match ssl_stream.ssl_read(&mut line) {
                    Ok(n) => {
                        let recv = &String::from_utf8_lossy(&line[0..n]).to_string();
                        debug!(target: &self.name, "SSL stream recv_trial {} ({}): {}", self.recv_trials, recv.len(), recv);
                        self.recv_trials = 0;
                        self.recv_payload.push_str(recv);
                    }
                    // TODO: Should we handle ErrorCode::ZERO_RETURN and other errors separately?
                    Err(e) => {
                        debug!(target: &self.name, "SSL stream read error: {}", e.to_string());
                    }
                }
                if let Err(_) = self.process_recv_payload(Some(ssl_stream)) {
                    return Err(CommandError::Fail);
                }
            }
            Command::SslConnectFail => {
                debug!(target: &self.name, "Received SslConnectFail command while connected");
                return Err(CommandError::Disconnect);
            }
            Command::Timeout => {
                debug!(target: &self.name, "Received Timeout command while connected");
                return Err(CommandError::Disconnect);
            }
            Command::Quit => {
                self.reset_command();
                return Err(CommandError::Quit);
            }
            Command::Fail => {
                self.reset_command();
                return Err(CommandError::Fail);
            }
            Command::KeepAlive => {
                self.reset_command();
            }
            Command::None => {
                return self.check_command_timeout();
            }
        }
        Ok(())
    }

    pub fn execute_tcp_command(&mut self, mut tcp_stream: &TcpStream) -> CommandResult {
        match self.cmd {
            Command::Send => {
                // TODO: Is it possible to handle send result similarly to recv? But we can call ssl_write() only once
                match tcp_stream.write(&self.payload.as_bytes()) {
                    Ok(n) => {
                        if self.payload.len() == n {
                            match tcp_stream.flush() {
                                Ok(()) => {
                                    if let Err(_) = self.report_cmd_result(None) {
                                        return Err(CommandError::Fail);
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
                return Err(CommandError::Fail);
            }
            Command::Recv => {
                let mut line = [0; BUF_SIZE];
                // Do not use read_to_string() or read_to_end() here, they don't read anything
                match tcp_stream.read(&mut line) {
                    Ok(n) => {
                        let recv = &String::from_utf8_lossy(&line[0..n]).to_string();
                        debug!(target: &self.name, "TCP stream recv_trial {} ({}): {}", self.recv_trials, recv.len(), recv);
                        if recv.is_empty() {
                            self.disconnect_detect_trials += 1;
                            trace!(target: &self.name, "TCP stream read disconnect detect trial: {}", self.disconnect_detect_trials);
                            if self.disconnect_detect_trials >= MAX_RECV_DISCONNECT_DETECT {
                                debug!(target: &self.name, "TCP stream read DISCONNECT detected");
                                self.recv_payload.push_str(recv);

                                if let Err(_) = self.report_cmd_result(None) {
                                    return Err(CommandError::Fail);
                                }
                                return Err(CommandError::Disconnect);
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
                    return Err(CommandError::Fail);
                }
            }
            Command::SslConnectFail => {
                debug!(target: &self.name, "Received SslConnectFail command while connected");
                return Err(CommandError::Disconnect);
            }
            Command::Timeout => {
                debug!(target: &self.name, "Received Timeout command while connected");
                return Err(CommandError::Disconnect);
            }
            Command::Quit => {
                self.reset_command();
                return Err(CommandError::Quit);
            }
            Command::Fail => {
                self.reset_command();
                return Err(CommandError::Fail);
            }
            Command::KeepAlive => {
                self.reset_command();
            }
            Command::None => {
                return self.check_command_timeout();
            }
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
        debug!(target: &self.name, "SSL stream current_cipher name: {}, standard_name: {}, version: {}, cipher_nid: {:?}", cipher.name(), cipher.standard_name().unwrap_or(""), cipher.version(), cipher.cipher_nid().unwrap_or(Nid::UNDEF));
        debug!(target: &self.name, "SSL stream current_cipher description: {}", cipher.description());
        debug!(target: &self.name, "SSL stream version_str {}", ssl.version_str());
        debug!(target: &self.name, "SSL stream state_string {}", ssl.state_string());
        //debug!(target: &self.name, "SSL stream state_string_long {}", ssl.state_string_long());
        // SNI sent by client
        debug!(target: &self.name, "SSL stream servername {}", ssl.servername(NameType::HOST_NAME).unwrap_or(""));
        //debug!(target: &self.name, "SSL stream time: {:#?}, timeout: {:#?}", ssl.session().unwrap().time(), ssl.session().unwrap().timeout());

        match ssl.peer_certificate() {
            Some(peer_cert) => {
                // TODO: Check why all peer.cert entry methods give the same entries
                let pcv: Vec<String> = peer_cert.issuer_name().entries().map(|x| x.data().as_utf8().unwrap().to_string()).collect();
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
        if self.assert.contains_key("sni_servername") {
            failed |= self.assert_str("sni_servername", ssl.servername(NameType::HOST_NAME).unwrap_or(""));
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

pub fn str2sslversion(s: &str) -> SslVersion {
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
pub fn ssl_nid_by_name(s: &str) -> i32 {
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
