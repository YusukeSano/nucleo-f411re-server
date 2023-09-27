use core::convert::TryInto;

use crate::{util, Error, Result};

#[derive(Copy, Clone)]
pub enum Udp<'a> {
    Raw(&'a [u8]),
}

pub struct UdpPdu {
    buffer: [u8; 1480],
    inner_size: usize,
}

impl UdpPdu {
    pub fn new() -> Self {
        UdpPdu {
            buffer: [0u8; 1480],
            inner_size: 0,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..8 + self.inner_size]
    }

    pub fn source_port(&mut self, value: u16) {
        self.buffer[0..=1].copy_from_slice(&value.to_be_bytes());
    }

    pub fn destination_port(&mut self, value: u16) {
        self.buffer[2..=3].copy_from_slice(&value.to_be_bytes());
    }

    pub fn length(&mut self, value: u16) {
        self.buffer[4..=5].copy_from_slice(&value.to_be_bytes());
    }

    fn compute_length(&mut self) {
        self.length((8 + self.inner_size) as u16);
    }

    pub fn checksum(&mut self, value: u16) {
        self.buffer[6..=7].copy_from_slice(&value.to_be_bytes());
    }

    pub fn compute_checksum(&mut self, ip: &crate::IpPseudoHeader) {
        let mut csum = match ip {
            crate::IpPseudoHeader::Ipv4(ipv4) => util::checksum(&[
                &ipv4.source_address.as_ref(),
                &ipv4.destination_address.as_ref(),
                &[0x00, ipv4.protocol].as_ref(),
                &self.buffer[4..=5],
                &self.buffer[0..=5],
                &self.buffer[8..8 + self.inner_size],
            ]),
        };
        if csum == 0 {
            csum = 0xFFFF
        }
        self.checksum(csum);
    }

    pub fn inner(&mut self, value: &[u8]) -> Result<()> {
        let len = value.len();
        if len > 1472 {
            return Err(Error::Oversized);
        }
        self.inner_size = len;
        self.compute_length();
        self.buffer[8..8 + len].copy_from_slice(value);
        Ok(())
    }
}

#[derive(Copy, Clone)]
pub struct UdpParser<'a> {
    buffer: &'a [u8],
}

impl<'a> UdpParser<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        let pdu = UdpParser { buffer };
        if buffer.len() < 8 {
            return Err(Error::Truncated);
        }
        Ok(pdu)
    }

    pub fn inner(&'a self) -> Result<Udp<'a>> {
        self.clone().into_inner()
    }

    pub fn into_inner(self) -> Result<Udp<'a>> {
        let rest = &self.buffer[8..self.length() as usize];
        Ok(Udp::Raw(rest))
    }

    pub fn source_port(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[0..=1].try_into().unwrap())
    }

    pub fn destination_port(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[2..=3].try_into().unwrap())
    }

    pub fn length(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[4..=5].try_into().unwrap())
    }

    pub fn checksum(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[6..=7].try_into().unwrap())
    }

    pub fn computed_checksum(&'a self, ip: &crate::Ip) -> u16 {
        let csum = match ip {
            crate::Ip::Ipv4(ipv4) => util::checksum(&[
                &ipv4.source_address().as_ref(),
                &ipv4.destination_address().as_ref(),
                &[0x00, ipv4.protocol()].as_ref(),
                &self.length().to_be_bytes().as_ref(),
                &self.buffer[0..=5],
                &self.buffer[8..],
            ]),
        };
        if csum == 0 {
            0xFFFF
        } else {
            csum
        }
    }
}
