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
use std::io::Error;
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::sync::mpsc;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::mpsc::Sender;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use openssl::ec::{EcKey, EcKeyRef};
use openssl::nid::Nid;
use openssl::pkey::Params;
use openssl::ssl::{ShutdownState, SslConnector, SslFiletype, SslMethod, SslOptions, SslStream, SslVerifyMode};

use testend::{CmdExecResult, Command, MAX_CMD_TRIALS, MAX_STREAM_CONNECT_TRIALS, Msg, Proto, ProtoConfig, ssl_nid_by_name, str2sslversion, TestEndBase, WAIT_STREAM_CONNECT};

pub struct Client {
    base: TestEndBase,
}

impl Client {
    pub fn new(hid: i32, sid: i32, cid: i32, tid: i32, cli2mgr_tx: Sender<Msg>, mgr2cli_rx: Arc<Mutex<mpsc::Receiver<Msg>>>, proto: ProtoConfig, config: BTreeMap<String, String>) -> Self {
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

            match scc.connect(&self.base.proto.sni_servername, tcp_stream) {
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

    pub fn run(&mut self) -> bool {
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
