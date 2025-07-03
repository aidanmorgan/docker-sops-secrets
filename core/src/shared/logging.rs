use log::{LevelFilter, Log, Metadata, Record};
use std::io::{self, Write};

pub struct InsecureLogger {
    level: LevelFilter,
}

impl InsecureLogger {
    pub fn new(level: LevelFilter) -> Self {
        Self { level }
    }
}

impl Log for InsecureLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    #[allow(dead_code)]
    // disbling the linter here, depending on which flag is used different variables are used
    fn log(&self, record: &Record) {
        // this isn't strictly required as the default implementation of `enabled` already
        // does this check, but I'm being paranoid and just making doubly sure it doesn't happen.
        #[cfg(feature = "insecure_mode")]
        {
            if self.enabled(record.metadata()) {
                let mut stderr = io::stderr();
                let _ = writeln!(
                    stderr,
                    "[{}] {}:{} - {}",
                    record.level(),
                    record.file().unwrap_or("unknown"),
                    record.line().unwrap_or(0),
                    record.args()
                );
            }
        }

        #[cfg(feature = "secure_mode")]
        {
            // we only allow errors to be logged in secure mode.
            if record.level() == LevelFilter::Error {
                let mut stderr = io::stderr();
                let _ = writeln!(
                    stderr,
                    "[{}] {}:{} - {}",
                    record.level(),
                    record.file().unwrap_or("unknown"),
                    record.line().unwrap_or(0),
                    record.args()
                );
            }
        }

        #[cfg(not(any(feature = "secure_mode", feature = "insecure_mode")))]
        {
            panic!("Code must be built with either secure or insecure mode.")
        }
    }

    fn flush(&self) {
        let _ = io::stderr().flush();
    }
}

pub fn init_logger() {
    #[cfg(feature = "insecure_mode")]
    {
        let logger = InsecureLogger::new(LevelFilter::Info);
        log::set_boxed_logger(Box::new(logger))
            .map(|()| log::set_max_level(LevelFilter::Info))
            .expect("Failed to set logger");
    }

    #[cfg(not(feature = "insecure_mode"))]
    {
        // In secure mode, dont log anything!
        log::set_max_level(LevelFilter::Error);
    }
}
