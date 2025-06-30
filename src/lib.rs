#[macro_use]
pub mod server;
pub mod client;
#[macro_use]
pub mod shared;

#[cfg(feature = "test_logging")]
#[macro_export]
macro_rules! test_log {
    ($($arg:tt)*) => {
        eprintln!("[TEST_LOG] {}", format!($($arg)*));
    };
}

#[cfg(not(feature = "test_logging"))]
#[macro_export]
macro_rules! test_log {
    ($($arg:tt)*) => {};
}
