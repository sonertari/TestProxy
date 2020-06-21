// Copyright (C) 2019, 2020 Soner Tari <sonertari@gmail.com>
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

use std::path::PathBuf;

use structopt::StructOpt;

#[derive(StructOpt, Debug, Clone, Eq, PartialEq)]
#[structopt(
    author = "Soner Tari <sonertari@gmail.com>",
    about = "Tool for end-to-end testing of proxy servers",
)]
pub struct Config {
    /// Load test harnesses from file
    #[structopt(
        short = "f",
        long = "testharness",
        takes_value = true,
        value_name = "FILENAME",
    )]
    pub testharness: PathBuf,

    /// Set log level, between 0 (none) and 5 (verbose)
    #[structopt(
        short = "l",
        long = "level",
        takes_value = true,
        value_name = "LEVEL",
        default_value = "3",
        raw(possible_values = r#"&["0", "1", "2", "3", "4", "5"]"#)
    )]
    pub verbosity: i32,

    /// Format for displaying date and time in log messages. Type `man
    /// strftime` to see the format specification
    #[structopt(
        short = "d",
        long = "datetime-format",
        takes_value = true,
        value_name = "STRING",
        default_value = "%X",
        parse(try_from_str = "parse_datetime_format")
    )]
    pub date_time_format: String,
}

fn parse_datetime_format(s: &str) -> Result<String, time::ParseError> {
    time::strftime(s, &time::now()).map(|_| String::from(s))
}
