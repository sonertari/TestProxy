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
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::mpsc;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::mpsc::Sender;
use std::sync::Mutex;
use std::thread;

use openssl::ec::{EcKey, EcKeyRef};
use openssl::nid::Nid;
use openssl::pkey::Params;
use openssl::ssl::{HandshakeError, ShutdownState, SslAcceptor, SslFiletype, SslMethod, SslOptions, SslStream, SslVerifyMode};

use testend::{CmdExecResult, Command, MAX_CMD_TRIALS, MAX_CONNECT_TIMEOUT_TRIALS, MAX_STREAM_CONNECT_TRIALS, Msg, Proto, ProtoConfig, ssl_nid_by_name, str2sslversion, TestEndBase, WAIT_STREAM_CONNECT};

pub struct Server {
    hid: i32,
    sid: i32,
    cid: i32,
    tid: i32,
    base: TestEndBase,
}

impl Server {
    pub fn new(hid: i32, sid: i32, cid: i32, tid: i32, srv2mgr_tx: Sender<Msg>, mgr2srv_rx: Arc<Mutex<mpsc::Receiver<Msg>>>, proto: ProtoConfig, config: BTreeMap<String, String>) -> Self {
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
                        // Fail only if we are executing a command
                        *failed = self.base.cmd != Command::None;
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

    pub fn run(&mut self) -> bool {
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
