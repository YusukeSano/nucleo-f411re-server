use core::convert::TryInto;

use crate::{util, Error, Result};

#[derive(Copy, Clone)]
pub enum Ip<'a> {
    Ipv4(Ipv4Parser<'a>),
}

impl<'a> Ip<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.is_empty() {
            return Err(Error::Truncated);
        }
        match buffer[0] >> 4 {
            4 => Ok(Ip::Ipv4(Ipv4Parser::parse(buffer)?)),
            _ => Err(Error::Malformed),
        }
    }
}

#[derive(Copy, Clone)]
pub enum Ipv4<'a> {
    Raw(&'a [u8]),
}

pub struct Ipv4Pdu {
    buffer: [u8; 1500],
    inner_size: usize,
}

impl Ipv4Pdu {
    pub fn new() -> Self {
        let mut ipv4_pdu = Ipv4Pdu {
            buffer: [0u8; 1500],
            inner_size: 0,
        };
        ipv4_pdu.version(0x04);
        ipv4_pdu.ihl(0x05);
        ipv4_pdu.ttl(0x40);
        ipv4_pdu.compute_total_length();
        ipv4_pdu
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..self.computed_ihl() + self.inner_size]
    }

    pub fn version(&mut self, value: u8) {
        let version = self.buffer[0] & 0xF | value << 4;
        self.buffer[0] = version;
    }

    pub fn ihl(&mut self, value: u8) {
        let ihl = self.buffer[0] & 0xF0 | value & 0xF;
        self.buffer[0] = ihl;
    }

    fn computed_ihl(&self) -> usize {
        (self.buffer[0] & 0xF) as usize * 4
    }

    pub fn dscp(&mut self, value: u8) {
        let dscp = self.buffer[1] & 0x3 | value << 2;
        self.buffer[1] = dscp;
    }

    pub fn ecn(&mut self, value: u8) {
        let ecn = self.buffer[1] & 0xFC | value & 0x3;
        self.buffer[1] = ecn;
    }

    pub fn total_length(&mut self, value: u16) {
        self.buffer[2..=3].copy_from_slice(&value.to_be_bytes());
    }

    fn compute_total_length(&mut self) {
        self.total_length((self.inner_size + self.computed_ihl()) as u16);
    }

    pub fn identification(&mut self, value: u16) {
        self.buffer[4..=5].copy_from_slice(&value.to_be_bytes());
    }

    pub fn dont_fragment(&mut self, value: bool) {
        let dont_fragment = if value {
            self.buffer[6] | 0x40
        } else {
            self.buffer[6] & 0xBF
        };
        self.buffer[6] = dont_fragment;
    }

    pub fn more_fragments(&mut self, value: bool) {
        let more_fragments = if value {
            self.buffer[6] | 0x20
        } else {
            self.buffer[6] & 0xDF
        };
        self.buffer[6] = more_fragments;
    }

    pub fn fragment_offset(&mut self, value: u16) {
        let fragment_offset = u16::from_be_bytes([self.buffer[6] & 0xE0, 0x00]) | value & 0x1FFF;
        self.buffer[6..=7].copy_from_slice(&fragment_offset.to_be_bytes());
    }

    pub fn ttl(&mut self, value: u8) {
        self.buffer[8] = value;
    }

    pub fn protocol(&mut self, value: u8) {
        self.buffer[9] = value;
    }

    pub fn checksum(&mut self, value: u16) {
        self.buffer[10..=11].copy_from_slice(&value.to_be_bytes());
    }

    pub fn compute_checksum(&mut self) {
        self.checksum(util::checksum(&[
            &self.buffer[0..=9],
            &self.buffer[12..self.computed_ihl()],
        ]))
    }

    pub fn source_address(&mut self, value: [u8; 4]) {
        self.buffer[12..=15].copy_from_slice(&value);
    }

    pub fn destination_address(&mut self, value: [u8; 4]) {
        self.buffer[16..=19].copy_from_slice(&value);
    }

    pub fn options(&mut self, value: &[u8]) {
        let len = value.len();
        let ihl = (20 + len + (20 + len) % 4) / 4;
        self.ihl(ihl as u8);
        self.compute_total_length();
        self.buffer[20..20 + len].copy_from_slice(value);
    }

    pub fn inner(&mut self, value: &[u8]) -> Result<()> {
        let ihl = self.computed_ihl();
        let len = value.len();
        if len > 1500 - ihl {
            return Err(Error::Oversized);
        }
        self.inner_size = len;
        self.compute_total_length();
        self.buffer[ihl..ihl + len].copy_from_slice(value);
        Ok(())
    }
}

#[derive(Copy, Clone)]
pub struct Ipv4Parser<'a> {
    buffer: &'a [u8],
}

impl<'a> Ipv4Parser<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        let pdu = Ipv4Parser { buffer };
        if buffer.len() < 20 || pdu.computed_ihl() < 20 {
            return Err(Error::Truncated);
        }
        if buffer.len() < (pdu.computed_ihl() as usize)
            || (pdu.total_length() as usize) < pdu.computed_ihl()
        {
            return Err(Error::Malformed);
        }
        if pdu.version() != 4 {
            return Err(Error::Malformed);
        }
        Ok(pdu)
    }

    pub fn inner(&'a self) -> Result<Ipv4<'a>> {
        self.clone().into_inner()
    }

    pub fn into_inner(self) -> Result<Ipv4<'a>> {
        let rest = &self.buffer[self.computed_ihl()..];

        if self.fragment_offset() > 0 {
            Ok(Ipv4::Raw(rest))
        } else {
            Ok(match self.protocol() {
                _ => Ipv4::Raw(rest),
            })
        }
    }

    pub fn version(&'a self) -> u8 {
        self.buffer[0] >> 4
    }

    pub fn ihl(&'a self) -> u8 {
        self.buffer[0] & 0xF
    }

    pub fn computed_ihl(&'a self) -> usize {
        self.ihl() as usize * 4
    }

    pub fn dscp(&'a self) -> u8 {
        self.buffer[1] >> 2
    }

    pub fn ecn(&'a self) -> u8 {
        self.buffer[1] & 0x3
    }

    pub fn total_length(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[2..=3].try_into().unwrap())
    }

    pub fn identification(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[4..=5].try_into().unwrap())
    }

    pub fn dont_fragment(&'a self) -> bool {
        self.buffer[6] & 0x40 != 0
    }

    pub fn more_fragments(&'a self) -> bool {
        self.buffer[6] & 0x20 != 0
    }

    pub fn fragment_offset(&'a self) -> u16 {
        u16::from_be_bytes([self.buffer[6] & 0x1f, self.buffer[7]])
    }

    pub fn computed_fragment_offset(&'a self) -> u16 {
        self.fragment_offset() * 8
    }

    pub fn ttl(&'a self) -> u8 {
        self.buffer[8]
    }

    pub fn protocol(&'a self) -> u8 {
        self.buffer[9]
    }

    pub fn checksum(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[10..=11].try_into().unwrap())
    }

    pub fn computed_checksum(&'a self) -> u16 {
        util::checksum(&[&self.buffer[0..=9], &self.buffer[12..self.computed_ihl()]])
    }

    pub fn source_address(&'a self) -> [u8; 4] {
        let mut source_address = [0u8; 4];
        source_address.copy_from_slice(&self.buffer[12..=15]);
        source_address
    }

    pub fn destination_address(&'a self) -> [u8; 4] {
        let mut destination_address = [0u8; 4];
        destination_address.copy_from_slice(&self.buffer[16..=19]);
        destination_address
    }

    pub fn options(&'a self) -> Ipv4OptionIterator<'a> {
        Ipv4OptionIterator {
            buffer: &self.buffer,
            pos: 20,
            ihl: self.computed_ihl(),
        }
    }
}

#[derive(Copy, Clone)]
pub enum Ipv4Option<'a> {
    Raw { option: u8, data: &'a [u8] },
}

#[derive(Copy, Clone)]
pub struct Ipv4OptionIterator<'a> {
    buffer: &'a [u8],
    pos: usize,
    ihl: usize,
}

impl<'a> Iterator for Ipv4OptionIterator<'a> {
    type Item = Ipv4Option<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos < self.ihl {
            let pos = self.pos;
            let option = self.buffer[pos];
            let len = match option {
                0 | 1 => 1usize,
                _ => {
                    if self.ihl <= (pos + 1) {
                        return None;
                    }
                    let len = self.buffer[pos + 1] as usize;
                    if len < 2 {
                        return None;
                    }
                    len
                }
            };
            if self.ihl < (pos + len) {
                return None;
            }
            self.pos += len;
            Some(Ipv4Option::Raw {
                option,
                data: &self.buffer[pos..(pos + len)],
            })
        } else {
            None
        }
    }
}

pub enum IpPseudoHeader {
    Ipv4(Ipv4PseudoHeader),
}

pub struct Ipv4PseudoHeader {
    pub source_address: [u8; 4],
    pub destination_address: [u8; 4],
    pub protocol: u8,
}
