#![no_std]

mod ethernet;
pub use ethernet::{Ethernet, EtherType, EthernetPdu, EthernetParser};

mod util;
pub use util::{crc32};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    Truncated,
    Oversized,
    Malformed,
}

pub type Result<T> = core::result::Result<T, Error>;
