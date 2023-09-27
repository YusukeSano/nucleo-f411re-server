use core::convert::TryInto;

use crate::{Error, Result};

#[allow(non_snake_case)]
pub mod ArpOpcode {
    pub const REQUEST: u16 = 1;
    pub const REPLY: u16 = 2;
}

pub struct ArpPdu {
    buffer: [u8; 28],
}

impl ArpPdu {
    pub fn new() -> Self {
        let mut arp_pdu = ArpPdu { buffer: [0u8; 28] };
        arp_pdu.hardware_type(0x0001);
        arp_pdu.protocol_type(0x0800);
        arp_pdu.hardware_length(0x06);
        arp_pdu.protocol_length(0x04);
        arp_pdu
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    pub fn hardware_type(&mut self, value: u16) {
        self.buffer[0..=1].copy_from_slice(&value.to_be_bytes());
    }

    pub fn protocol_type(&mut self, value: u16) {
        self.buffer[2..=3].copy_from_slice(&value.to_be_bytes());
    }

    pub fn hardware_length(&mut self, value: u8) {
        self.buffer[4] = value;
    }

    pub fn protocol_length(&mut self, value: u8) {
        self.buffer[5] = value;
    }

    pub fn opcode(&mut self, value: u16) {
        self.buffer[6..=7].copy_from_slice(&value.to_be_bytes());
    }

    pub fn sender_hardware_address(&mut self, value: [u8; 6]) {
        self.buffer[8..=13].copy_from_slice(&value);
    }

    pub fn sender_protocol_address(&mut self, value: [u8; 4]) {
        self.buffer[14..=17].copy_from_slice(&value);
    }

    pub fn target_hardware_address(&mut self, value: [u8; 6]) {
        self.buffer[18..=23].copy_from_slice(&value);
    }

    pub fn target_protocol_address(&mut self, value: [u8; 4]) {
        self.buffer[24..=27].copy_from_slice(&value);
    }
}

#[derive(Copy, Clone)]
pub struct ArpParser<'a> {
    buffer: &'a [u8],
}

impl<'a> ArpParser<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < 28 {
            return Err(Error::Truncated);
        }
        let pdu = ArpParser { buffer };
        if pdu.hardware_length() != 6 {
            // Supports only 6-octet hardware addresses
            return Err(Error::Malformed);
        }
        if pdu.protocol_length() != 4 {
            // Supports only 4-octet protocol addresses
            return Err(Error::Malformed);
        }
        Ok(pdu)
    }

    pub fn hardware_type(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[0..=1].try_into().unwrap())
    }

    pub fn protocol_type(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[2..=3].try_into().unwrap())
    }

    pub fn hardware_length(&'a self) -> u8 {
        self.buffer[4]
    }

    pub fn protocol_length(&'a self) -> u8 {
        self.buffer[5]
    }

    pub fn opcode(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[6..=7].try_into().unwrap())
    }

    pub fn sender_hardware_address(&'a self) -> [u8; 6] {
        let mut sender_hardware_address = [0u8; 6];
        sender_hardware_address.copy_from_slice(&self.buffer[8..=13]);
        sender_hardware_address
    }

    pub fn sender_protocol_address(&'a self) -> [u8; 4] {
        let mut sender_protocol_address = [0u8; 4];
        sender_protocol_address.copy_from_slice(&self.buffer[14..=17]);
        sender_protocol_address
    }

    pub fn target_hardware_address(&'a self) -> [u8; 6] {
        let mut target_hardware_address = [0u8; 6];
        target_hardware_address.copy_from_slice(&self.buffer[18..=23]);
        target_hardware_address
    }

    pub fn target_protocol_address(&'a self) -> [u8; 4] {
        let mut target_protocol_address = [0u8; 4];
        target_protocol_address.copy_from_slice(&self.buffer[24..=27]);
        target_protocol_address
    }
}
