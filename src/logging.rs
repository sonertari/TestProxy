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

use std::io;

use colored::Colorize;
use fern::colors::{Color, ColoredLevelConfig};
use fern::Dispatch;
use log::{Level, LevelFilter};

use super::config::Config;

pub fn configure_logging(config: &Config) {
    let colors = ColoredLevelConfig::new()
        .info(Color::Green)
        .warn(Color::Yellow)
        .error(Color::Red)
        .debug(Color::Magenta)
        .trace(Color::Cyan);
    let date_time_format = config.date_time_format.clone();

    Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{time}] [{level}] {sender}: {message}",
                time = time::strftime(&date_time_format, &time::now())
                    .unwrap()
                    .magenta(),
                level = colors.color(record.level()).to_string().underline(),
                sender = record.target().on_blue(),
                message = {
                    match record.level() {
                        Level::Error => format!("{}", message).on_red(),
                        Level::Warn => format!("{}", message).on_yellow(),
                        Level::Info => format!("{}", message).on_green(),
                        _ => format!("{}", message).normal(),
                    }
                },
            ));
        })
        // Send debugging information and traces to stderr
        .chain(
            Dispatch::new()
                .filter(move |metadata| match metadata.level() {
                    Level::Info | Level::Warn | Level::Error => false,
                    Level::Debug | Level::Trace => true,
                })
                .chain(io::stderr()),
        )
        // Send notifications, warnings, and errors to stdout
        .chain(
            Dispatch::new()
                .filter(move |metadata| match metadata.level() {
                    Level::Info | Level::Warn | Level::Error => true,
                    Level::Debug | Level::Trace => false,
                })
                .chain(io::stdout()),
        )
        .level(num2level(config.verbosity))
        .apply()
        .expect("Cannot apply logging config");
}

fn num2level(level: i32) -> LevelFilter {
    match level {
        0 => LevelFilter::Off,
        1 => LevelFilter::Error,
        2 => LevelFilter::Warn,
        3 => LevelFilter::Info,
        4 => LevelFilter::Debug,
        5 => LevelFilter::Trace,
        _ => panic!("Log level not supported"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_num2level() {
        assert_eq!(num2level(0), LevelFilter::Off);
        assert_eq!(num2level(1), LevelFilter::Error);
        assert_eq!(num2level(2), LevelFilter::Warn);
        assert_eq!(num2level(3), LevelFilter::Info);
        assert_eq!(num2level(4), LevelFilter::Debug);
        assert_eq!(num2level(5), LevelFilter::Trace);
    }
}
