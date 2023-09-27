use core::convert::TryInto;

use crate::{util, Error, Result};

#[allow(non_snake_case)]
pub mod EtherType {
    pub const DOT1Q: u16 = 0x8100;
}

#[derive(Copy, Clone)]
pub enum Ethernet<'a> {
    Raw(&'a [u8]),
}

pub struct EthernetPdu {
    buffer: [u8; 1522],
    inner_size: usize,
}

impl EthernetPdu {
    pub fn new(ethertype: u16) -> Self {
        let mut ethernet_pdu = EthernetPdu {
            buffer: [0u8; 1522],
            inner_size: 0,
        };
        if ethertype == EtherType::DOT1Q {
            ethernet_pdu.tpid(ethertype);
        } else {
            ethernet_pdu.ethertype(ethertype);
        }
        ethernet_pdu
    }

    pub fn as_bytes(&mut self) -> &[u8] {
        let len = if self.inner_size < 46 {
            46
        } else {
            self.inner_size
        } + self.computed_ihl();
        self.fcs(util::crc32(self.buffer[0..len].as_ref()));
        &self.buffer[..len + 4]
    }

    fn computed_ihl(&self) -> usize {
        match self.get_tpid() {
            EtherType::DOT1Q => 18,
            _ => 14,
        }
    }

    pub fn destination_address(&mut self, value: [u8; 6]) {
        self.buffer[0..=5].copy_from_slice(&value);
    }

    pub fn source_address(&mut self, value: [u8; 6]) {
        self.buffer[6..=11].copy_from_slice(&value);
    }

    pub fn tpid(&mut self, value: u16) {
        self.buffer[12..=13].copy_from_slice(&value.to_be_bytes());
    }

    fn get_tpid(&self) -> u16 {
        u16::from_be_bytes(self.buffer[12..=13].try_into().unwrap())
    }

    pub fn ethertype(&mut self, value: u16) {
        if self.get_tpid() == EtherType::DOT1Q {
            self.buffer[16..=17].copy_from_slice(&value.to_be_bytes());
        } else {
            self.buffer[12..=13].copy_from_slice(&value.to_be_bytes());
        }
    }

    pub fn vlan(&mut self, value: u16) {
        if self.get_tpid() == EtherType::DOT1Q {
            let vlan = u16::from_be_bytes(self.buffer[14..=15].try_into().unwrap()) & 0xF000
                | value & 0x0FFF;
            self.buffer[14..=15].copy_from_slice(&vlan.to_be_bytes());
        }
    }

    pub fn vlan_pcp(&mut self, value: u8) {
        if self.get_tpid() == EtherType::DOT1Q {
            let vlan_pcp = self.buffer[14] & 0x1F | value << 5;
            self.buffer[14] = vlan_pcp;
        }
    }

    pub fn vlan_dei(&mut self, value: bool) {
        if self.get_tpid() == EtherType::DOT1Q {
            let vlan_dei = if value {
                self.buffer[14] | 0x10
            } else {
                self.buffer[14] & 0xEF
            };
            self.buffer[14] = vlan_dei;
        }
    }

    pub fn fcs(&mut self, value: u32) {
        let inner_size = if self.inner_size < 46 {
            46
        } else {
            self.inner_size
        };
        let len = self.computed_ihl() + inner_size;
        self.buffer[len..len + 4].copy_from_slice(&value.to_be_bytes());
    }

    pub fn inner(&mut self, value: &[u8]) -> Result<()> {
        let len = value.len();
        if len > 1500 {
            return Err(Error::Oversized);
        }
        self.inner_size = len;
        let ihl = self.computed_ihl();
        self.buffer[ihl..ihl + len].copy_from_slice(value);
        Ok(())
    }
}

#[derive(Copy, Clone)]
pub struct EthernetParser<'a> {
    buffer: &'a [u8],
}

impl<'a> EthernetParser<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < 14 {
            return Err(Error::Truncated);
        }
        let pdu = EthernetParser { buffer };
        if pdu.tpid() == EtherType::DOT1Q && buffer.len() < 18 {
            return Err(Error::Truncated);
        }
        if pdu.ethertype() < 0x0600 {
            // 802.3 (LLC) frames are not supported
            return Err(Error::Malformed);
        }
        Ok(pdu)
    }

    pub fn inner(&'a self) -> Result<Ethernet<'a>> {
        self.clone().into_inner()
    }

    pub fn into_inner(self) -> Result<Ethernet<'a>> {
        let rest = &self.buffer[self.computed_ihl()..];
        Ok(match self.ethertype() {
            _ => Ethernet::Raw(rest),
        })
    }

    pub fn computed_ihl(&'a self) -> usize {
        match self.tpid() {
            EtherType::DOT1Q => 18,
            _ => 14,
        }
    }

    pub fn destination_address(&'a self) -> [u8; 6] {
        let mut destination_address = [0u8; 6];
        destination_address.copy_from_slice(&self.buffer[0..=5]);
        destination_address
    }

    pub fn source_address(&'a self) -> [u8; 6] {
        let mut source_address = [0u8; 6];
        source_address.copy_from_slice(&self.buffer[6..=11]);
        source_address
    }

    pub fn tpid(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[12..=13].try_into().unwrap())
    }

    pub fn ethertype(&'a self) -> u16 {
        match self.tpid() {
            EtherType::DOT1Q => u16::from_be_bytes(self.buffer[16..=17].try_into().unwrap()),
            ethertype => ethertype,
        }
    }

    pub fn vlan(&'a self) -> Option<u16> {
        match self.tpid() {
            EtherType::DOT1Q => {
                Some(u16::from_be_bytes(self.buffer[14..=15].try_into().unwrap()) & 0x0FFF)
            }
            _ => None,
        }
    }

    pub fn vlan_pcp(&'a self) -> Option<u8> {
        match self.tpid() {
            EtherType::DOT1Q => Some((self.buffer[14] & 0xE0) >> 5),
            _ => None,
        }
    }

    pub fn vlan_dei(&'a self) -> Option<bool> {
        match self.tpid() {
            EtherType::DOT1Q => Some(((self.buffer[14] & 0x10) >> 4) > 0),
            _ => None,
        }
    }
}
