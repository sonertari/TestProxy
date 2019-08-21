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
use std::fs::File;
use std::io::BufReader;
use std::thread;

use structopt::StructOpt;

use manager::Manager;
use testend::{TestHarnesses, TestSet};

use crate::config::Config;

mod manager;
mod client;
mod server;
mod testend;
mod config;
mod logging;

fn main() {
    openssl::init();
    openssl_probe::init_ssl_cert_env_vars();

    let config = Config::from_args();

    logging::configure_logging(&config);
    debug!("{:?}", config);

    let testharness_file = config.testharness.to_str().expect("Cannot convert test harness file name");
    let file = File::open(testharness_file).expect(&format!("Cannot open test harness file: {}", testharness_file));
    let reader = BufReader::new(file);
    let testharnesses: TestHarnesses = serde_json::from_reader(reader).expect(&format!("Cannot load test harness file: {}", testharness_file));

    warn!("{}", testharnesses.comment);

    let mut rv = 0;
    for (hid, testharness) in testharnesses.testharnesses {
        warn!("Start test harness {}: {}", hid, testharness.comment);

        let mut thread_handles = BTreeMap::new();
        for (sid, ref testset_file) in testharness.testsets {
            debug!("Spawn manager for test set {}", sid);

            let file = File::open(testset_file).expect(&format!("Cannot open test set file: {}", testset_file));
            let reader = BufReader::new(file);
            let testset: TestSet = serde_json::from_reader(reader).expect(&format!("Cannot load test set file: {}", testset_file));

            thread_handles.insert(sid, thread::spawn(move || Manager::new(hid, sid).run(testset)));
        }

        for (sid, t) in thread_handles {
            if let Ok(failed) = t.join() {
                if failed {
                    error!("Test set h{}.s{} failed", hid, sid);
                    rv = 1;
                }
            }
        }

        if rv == 1 {
            error!("Test harness {} failed: {}", hid, testharness.comment);
            break;
        }
    }
    std::process::exit(rv);
}
