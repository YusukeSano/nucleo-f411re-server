#![no_std]

mod ethernet;
pub use ethernet::{Ethernet, EtherType, EthernetPdu, EthernetParser};

mod arp;
pub use arp::{ArpOpcode, ArpPdu, ArpParser};

mod ip;
pub use ip::{Ip, IpPseudoHeader, Ipv4, Ipv4Option, Ipv4PseudoHeader, Ipv4Pdu, Ipv4Parser};

mod util;
pub use util::{checksum, crc32};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    Truncated,
    Oversized,
    Malformed,
}

pub type Result<T> = core::result::Result<T, Error>;
