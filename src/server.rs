// Copyright (C) 2019-2022 Soner Tari <sonertari@gmail.com>
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

use testend::{Command, CommandError, MAX_CONNECT_TIMEOUT_TRIALS, MAX_STREAM_CONNECT_TRIALS, Msg, Proto, ProtoConfig, ssl_nid_by_name, str2sslversion, TestEndBase, WAIT_STREAM_CONNECT};

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
            if self.base.prev_cmd == Command::Reconnect {
                debug!(target: &self.base.name, "Executing Reconnect command");
                self.base.prev_cmd = Command::None;
                break false;
            }

            if let Err(RecvTimeoutError::Disconnected) = self.base.get_command() {
                break false;
            }

            if let Err(e) = self.base.execute_tcp_command(&tcp_stream) {
                if e == CommandError::Fail {
                    *failed = true;
                } else if e == CommandError::Disconnect {
                    break false;
                }
                break true;
            }
            // TODO: How to determine if TcpStream is closed? Currently, we rely on Ok Result of empty read()
        }
    }

    fn configure_ssl(&self) -> SslAcceptor {
        let mut sab = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
        // Re-enable tls1 and tls11, which were disabled by mozilla_intermediate_v5()
        sab.clear_options(SslOptions::NO_TLSV1 | SslOptions::NO_TLSV1_1);

        if self.base.proto.verify_peer {
            sab.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
        } else {
            sab.set_verify(SslVerifyMode::NONE);
        }

        sab.set_certificate_file(&self.base.proto.crt, SslFiletype::PEM).expect("Cannot set crt file");
        sab.set_private_key_file(&self.base.proto.key, SslFiletype::PEM).expect("Cannot set key file");

        sab.set_cipher_list(&self.base.proto.cipher_list).expect("Cannot set cipher_list");
        sab.set_ciphersuites(&self.base.proto.ciphersuites).expect("Cannot set ciphersuites");

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

        if self.base.proto.set_ecdhcurve {
            let ecdh = EcKey::from_curve_name(Nid::from_raw(ssl_nid_by_name(&self.base.proto.ecdhcurve))).expect("Cannot create EcKey");
            // TODO: Is this the right way of typecasting to EcKeyRef, the compiler is fine with just &ecdh below, but the editor complains
            sab.set_tmp_ecdh(&ecdh as &EcKeyRef<Params>).expect("Cannot set ecdh");
        }

        sab.build()
    }

    fn run_ssl(&mut self, tcp_stream: &TcpStream, failed: &mut bool) -> bool {
        let mut exit = false;

        let acceptor = self.configure_ssl();

        // ATTENTION: Do not loop trying to accept the ssl stream, otherwise handshake fails
        let ssl_stream_result: Result<SslStream<&TcpStream>, HandshakeError<&TcpStream>> = match acceptor.accept(tcp_stream) {
            Ok(ssl_stream) => {
                debug!(target: &self.base.name, "SSL stream connected");
                Ok(ssl_stream)
            }
            Err(e) => {
                debug!(target: &self.base.name, "SSL stream connect HandshakeError: {}", e);
                // Fail only if we are executing an action command
                *failed = self.base.cmd != Command::None;
                Err(e)
            }
        };

        if let Ok(mut ssl_stream) = ssl_stream_result {
            self.base.cmd_trials = 0;
            exit = loop {
                if self.base.prev_cmd == Command::Reconnect {
                    debug!(target: &self.base.name, "Executing Reconnect command");
                    self.base.prev_cmd = Command::None;
                    break false;
                }

                if let Err(RecvTimeoutError::Disconnected) = self.base.get_command() {
                    break false;
                }

                if let Err(e) = self.base.execute_ssl_command(&mut ssl_stream) {
                    if e == CommandError::Fail {
                        *failed = true;
                    } else if e == CommandError::Disconnect {
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
            if let Err(e) = ssl_stream.shutdown() {
                debug!(target: &self.base.name, "SSL shutdown failed: {}", e);
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
        let mut failed = false;

        // nonblocking is necessary to get the next stream (connection)
        server.set_nonblocking(true).unwrap();

        // Manager will not start the tests until children reply the Ready command
        let mut exit = self.base.process_ready_command(&mut failed);

        if !exit && !failed {
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

                        if let Err(e) = tcp_stream.shutdown(Shutdown::Both) {
                            debug!(target: &self.base.name, "TCP shutdown failed: {}", e);
                        }
                    }
                    Err(e) => {
                        // Fail only if we are executing an action command
                        if !self.base.cmd.is_action_command() {
                            trace!(target: &self.base.name, "TCP stream error without cmd ({}): {}", tcp_stream_trials, e.to_string());
                        } else {
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
                        }
                        thread::sleep(WAIT_STREAM_CONNECT);
                    }
                }

                if let Err(RecvTimeoutError::Disconnected) = self.base.get_command() {
                    break;
                }

                if let Err(e) = self.base.execute_non_action_command() {
                    if e == CommandError::Fail {
                        failed = true;
                    }
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

#[cfg(test)]
mod tests {
    use testend::tests::create_testendbase_params;

    use super::*;

    #[test]
    fn test_name() {
        let (mut tc, proto, tx, rx) = create_testendbase_params();
        tc.server.insert("ip".to_string(), "".to_string());
        tc.server.insert("port".to_string(), "".to_string());

        let server = Server::new(1, 1, 1, 1, tx.clone(), Arc::clone(&rx),
                                 proto.clone(), tc.server.clone());

        assert_eq!(server.base.name, "SRV.h1.s1.c1.t1.0");
        assert_eq!(server.name(1), "SRV.h1.s1.c1.t1.1");
        // the name() method does not update the name field
        assert_eq!(server.base.name, "SRV.h1.s1.c1.t1.0");
    }
}
