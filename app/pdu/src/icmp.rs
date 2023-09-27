use core::convert::TryInto;

use crate::{util, Error, Result};

#[allow(non_snake_case)]
pub mod IcmpType {
    pub const ECHO_REPLY: u8 = 0;
    pub const ECHO_REQUEST: u8 = 8;
}

#[derive(Copy, Clone)]
pub enum Icmp<'a> {
    Raw(&'a [u8]),
}

pub struct IcmpPdu {
    buffer: [u8; 1480],
    inner_size: usize,
}

impl IcmpPdu {
    pub fn new() -> Self {
        IcmpPdu {
            buffer: [0u8; 1480],
            inner_size: 0,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..4 + self.inner_size]
    }

    pub fn message_type(&mut self, value: u8) {
        self.buffer[0] = value;
    }

    pub fn message_code(&mut self, value: u8) {
        self.buffer[1] = value;
    }

    pub fn checksum(&mut self, value: u16) {
        self.buffer[2..=3].copy_from_slice(&value.to_be_bytes());
    }

    pub fn compute_checksum(&mut self) {
        self.checksum(util::checksum(&[
            &self.buffer[0..=1],
            &self.buffer[4..4 + self.inner_size],
        ]));
    }

    pub fn inner(&mut self, value: &[u8]) -> Result<()> {
        let len = value.len();
        if len > 1476 {
            return Err(Error::Oversized);
        }
        self.inner_size = len;
        self.buffer[4..4 + len].copy_from_slice(value);
        Ok(())
    }
}

#[derive(Copy, Clone)]
pub struct IcmpParser<'a> {
    buffer: &'a [u8],
}

impl<'a> IcmpParser<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < 8 {
            return Err(Error::Truncated);
        }
        Ok(IcmpParser { buffer })
    }

    pub fn inner(&'a self) -> Result<Icmp<'a>> {
        self.clone().into_inner()
    }

    pub fn into_inner(self) -> Result<Icmp<'a>> {
        let rest = &self.buffer[4..];
        Ok(Icmp::Raw(rest))
    }

    pub fn message_type(&'a self) -> u8 {
        self.buffer[0]
    }

    pub fn message_code(&'a self) -> u8 {
        self.buffer[1]
    }

    pub fn checksum(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[2..=3].try_into().unwrap())
    }

    pub fn computed_checksum(&'a self) -> u16 {
        util::checksum(&[&self.buffer[0..=1], &self.buffer[4..]])
    }
}
