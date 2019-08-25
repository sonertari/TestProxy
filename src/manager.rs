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
use std::fs;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Mutex;
use std::thread;

use serde_json::Value;

use client::Client;
use server::Server;
use testend::{Assertion, CHANNEL_TIMEOUT, Command, CONNECT_TIMEOUT, MAX_TEST_TRIALS, Msg, Proto, ProtoConfig, READ_TIMEOUT, RecvMsgResult, SendCommandResult, TestConfig, TestEnd, TestSet, TestState, WRITE_TIMEOUT};

pub struct Manager {
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
    pub fn new(hid: i32, sid: i32) -> Self {
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
        let mut sni_servername = "localhost".to_string();
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
        let mut set_ecdhcurve = false;

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
            if testconfig.proto.contains_key("sni_servername") {
                sni_servername = testconfig.proto["sni_servername"].clone();
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
                set_ecdhcurve = true;
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
            sni_servername,
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
            set_ecdhcurve,
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
            let mut payload_file = "";
            // payload_file has precedence over payload, if both exist
            if state.get("payload_file") != None {
                payload_file = state["payload_file"].as_str().unwrap();
                payload = String::from_utf8_lossy(&fs::read(payload_file).expect(&format!("Cannot load payload file: {}", payload_file))).to_string();
            } else if state.get("payload") != None {
                payload = state["payload"].as_str().unwrap().to_string();
            } else {
                warn!(target: &self.name, "No payload defined, assuming empty payload");
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

    /// Sends the next command in the current test if any, or sends Quit otherwise
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

    /// Receives execution results from test ends, and decides what to do next
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
                        if !self.test_failed && test_succeeded {
                            return RecvMsgResult::SendCommand;
                        }
                        return RecvMsgResult::Quit;
                    }
                }
            }
            Err(e) => {
                trace!(target: &self.name, "Channel recv timeout on {}: {}", testend, e.to_string());
                return RecvMsgResult::NoMsg;
            }
        }
    }

    fn send_server_ready(&mut self) {
        self.testend = TestEnd::Server;
        self.cmd = Command::Ready;
        self.payload = "".to_string();
        self.assert = BTreeMap::new();
        self.mgr2srv_tx.send(Msg::from_cmd(Command::Ready)).unwrap();
    }

    fn send_client_ready(&mut self) {
        self.testend = TestEnd::Client;
        self.cmd = Command::Ready;
        self.payload = "".to_string();
        self.assert = BTreeMap::new();
        self.mgr2cli_tx.send(Msg::from_cmd(Command::Ready)).unwrap();
    }

    /// Waits test ends to be up and running before starting tests
    /// So sends a Ready command to each test end and receives replies from them
    fn wait_children_bootup(&mut self) -> Result<(), ()> {
        let mut wait_children_bootup_trials = 0;
        let mut server_ready = false;
        let mut client_ready = false;

        self.send_server_ready();
        loop {
            if self.testend == TestEnd::Server {
                if let RecvMsgResult::SendCommand = self.recv_msg(TestEnd::Server) {
                    server_ready = true;
                    wait_children_bootup_trials = 0;
                    self.send_client_ready();
                }
            }

            // Do not use else here, send_client_ready() may set testend above
            if self.testend == TestEnd::Client {
                if let RecvMsgResult::SendCommand = self.recv_msg(TestEnd::Client) {
                    client_ready = true;
                    wait_children_bootup_trials = 0;
                }
            }

            if server_ready && client_ready {
                break Ok(());
            }

            wait_children_bootup_trials += 1;
            trace!(target: &self.name, "Wait children bootup loop trial {}", wait_children_bootup_trials);
            if wait_children_bootup_trials > 10 {
                error!(target: &self.name, "Wait children bootup loop timed out");
                self.test_failed = true;
                // Send quit command to both ends
                self.mgr2srv_tx.send(Msg::from_cmd(Command::Quit)).unwrap();
                self.mgr2cli_tx.send(Msg::from_cmd(Command::Quit)).unwrap();
                break Err(());
            }
        }
    }

    /// Sends test commands to test ends and receives execution results
    /// We wait for messages from both test end at all times,
    /// not just from the test end executing the current test command,
    /// because the other test end may decide to quit the test and send a quit message
    fn run_test(&mut self) {
        // Send the first step of the test before starting to loop
        if let SendCommandResult::Success = self.send_next_command() {
            let mut test_trials = 0;
            loop {
                match self.recv_msg(TestEnd::Server) {
                    RecvMsgResult::SendCommand => {
                        if let SendCommandResult::TestFinished = self.send_next_command() {
                            break;
                        }
                        test_trials = 0;
                    }
                    RecvMsgResult::Quit => {
                        // Send quit command to the other end
                        self.send_command(&TestEnd::Client, Msg::from_cmd(Command::Quit));
                        break;
                    }
                    RecvMsgResult::NoMsg => {}
                }
                match self.recv_msg(TestEnd::Client) {
                    RecvMsgResult::SendCommand => {
                        if let SendCommandResult::TestFinished = self.send_next_command() {
                            break;
                        }
                        test_trials = 0;
                    }
                    RecvMsgResult::Quit => {
                        // Send quit command to the other end
                        self.send_command(&TestEnd::Server, Msg::from_cmd(Command::Quit));
                        break;
                    }
                    RecvMsgResult::NoMsg => {}
                }

                test_trials += 1;
                trace!(target: &self.name, "Test loop trial {}", test_trials);
                if test_trials > MAX_TEST_TRIALS {
                    error!(target: &self.name, "Test loop timed out");
                    self.test_failed = true;
                    break;
                }

                // Reduce keepalive frequency by 10 folds
                if test_trials % 10 == 0 {
                    // Send keepalive command to the test end waiting for its turn, otherwise its command loop may time out
                    self.send_command(if self.testend == TestEnd::Client { &TestEnd::Server } else { &TestEnd::Client },
                                      Msg::from_cmd(Command::KeepAlive));
                }
            }
        }
    }

    /// Starts the threads for client and server test ends, clones the current test, and runs it
    /// Consumes the final messages on the mpsc channels of test ends and joins the test end threads before exiting
    pub fn run(&mut self, testset: TestSet) -> bool {
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

                // Wait until children are up and running before starting tests
                if let Ok(()) = self.wait_children_bootup() {
                    self.clone_test(test);
                    self.run_test();
                }

                // TODO: Consume all messages in the channel and destroy the channel (?)
                // Consume any last message in the channels, otherwise mgr thread cannot return (?)
                self.recv_msg(TestEnd::Server);
                self.recv_msg(TestEnd::Client);

                if let Ok(failed) = server_thread.join() {
                    self.test_failed |= failed;
                }
                if let Ok(failed) = client_thread.join() {
                    self.test_failed |= failed;
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
        debug!(target: &self.name, "Return {}", self.test_failed);
        self.test_failed
    }
}
