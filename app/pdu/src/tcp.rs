use core::convert::TryInto;

use crate::{util, Error, Result};

#[allow(non_snake_case)]
pub mod TcpFlag {
    pub const FIN: u8 = 1;
    pub const SYN: u8 = 2;
    pub const RST: u8 = 4;
    pub const PSH: u8 = 8;
    pub const ACK: u8 = 16;
    pub const URG: u8 = 32;
    pub const ECN: u8 = 64;
    pub const CWR: u8 = 128;
}

#[derive(Copy, Clone)]
pub enum Tcp<'a> {
    Raw(&'a [u8]),
}

pub struct TcpPdu {
    buffer: [u8; 1480],
    inner_size: usize,
}

impl TcpPdu {
    pub fn new() -> Self {
        let mut tcp_pdu = TcpPdu {
            buffer: [0u8; 1480],
            inner_size: 0,
        };
        tcp_pdu.data_offset(0x05);
        tcp_pdu.window_size(0xFFFF);
        tcp_pdu
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..self.computed_data_offset() + self.inner_size]
    }

    pub fn source_port(&mut self, value: u16) {
        self.buffer[0..=1].copy_from_slice(&value.to_be_bytes());
    }

    pub fn destination_port(&mut self, value: u16) {
        self.buffer[2..=3].copy_from_slice(&value.to_be_bytes());
    }

    pub fn sequence_number(&mut self, value: u32) {
        self.buffer[4..=7].copy_from_slice(&value.to_be_bytes());
    }

    pub fn acknowledgement_number(&mut self, value: u32) {
        self.buffer[8..=11].copy_from_slice(&value.to_be_bytes());
    }

    pub fn data_offset(&mut self, value: u8) {
        let data_offset = self.buffer[12] & 0xF | value << 4;
        self.buffer[12] = data_offset;
    }

    fn computed_data_offset(&self) -> usize {
        (self.buffer[12] >> 4) as usize * 4
    }

    pub fn flags(&mut self, value: u8) {
        self.buffer[13] = value;
    }

    pub fn fin(&mut self, value: bool) {
        self.flags(if value {
            self.buffer[13] | 0x1
        } else {
            self.buffer[13] & 0xFE
        });
    }

    pub fn syn(&mut self, value: bool) {
        self.flags(if value {
            self.buffer[13] | 0x2
        } else {
            self.buffer[13] & 0xFD
        });
    }

    pub fn rst(&mut self, value: bool) {
        self.flags(if value {
            self.buffer[13] | 0x4
        } else {
            self.buffer[13] & 0xFB
        });
    }

    pub fn psh(&mut self, value: bool) {
        self.flags(if value {
            self.buffer[13] | 0x8
        } else {
            self.buffer[13] & 0xF7
        });
    }

    pub fn ack(&mut self, value: bool) {
        self.flags(if value {
            self.buffer[13] | 0x10
        } else {
            self.buffer[13] & 0xEF
        });
    }

    pub fn urg(&mut self, value: bool) {
        self.flags(if value {
            self.buffer[13] | 0x20
        } else {
            self.buffer[13] & 0xDF
        });
    }

    pub fn ecn(&mut self, value: bool) {
        self.flags(if value {
            self.buffer[13] | 0x40
        } else {
            self.buffer[13] & 0xBF
        });
    }

    pub fn cwr(&mut self, value: bool) {
        self.flags(if value {
            self.buffer[13] | 0x80
        } else {
            self.buffer[13] & 0x7F
        });
    }

    pub fn window_size(&mut self, value: u16) {
        self.buffer[14..=15].copy_from_slice(&value.to_be_bytes());
    }

    pub fn checksum(&mut self, value: u16) {
        self.buffer[16..=17].copy_from_slice(&value.to_be_bytes());
    }

    pub fn compute_checksum(&mut self, ip: &crate::IpPseudoHeader) {
        let csum = match ip {
            crate::IpPseudoHeader::Ipv4(ipv4) => util::checksum(&[
                &ipv4.source_address.as_ref(),
                &ipv4.destination_address.as_ref(),
                &[0x00, ipv4.protocol].as_ref(),
                &(self.computed_data_offset() + self.inner_size)
                    .to_be_bytes()
                    .as_ref(),
                &self.buffer[0..=15],
                &self.buffer[18..self.computed_data_offset() + self.inner_size],
            ]),
        };
        self.checksum(csum);
    }

    pub fn urgent_pointer(&mut self, value: u16) {
        self.buffer[18..=19].copy_from_slice(&value.to_be_bytes());
    }

    pub fn options(&mut self, value: &[u8]) {
        let len = value.len();
        let data_offset = (20 + len + (20 + len) % 4) / 4;
        self.data_offset(data_offset as u8);
        self.buffer[20..20 + len].copy_from_slice(value);
    }

    pub fn inner(&mut self, value: &[u8]) -> Result<()> {
        let data_offset = self.computed_data_offset();
        let len = value.len();
        if len > 1480 - data_offset {
            return Err(Error::Oversized);
        }
        self.inner_size = len;
        self.buffer[data_offset..data_offset + len].copy_from_slice(value);
        Ok(())
    }
}

#[derive(Copy, Clone)]
pub struct TcpParser<'a> {
    buffer: &'a [u8],
}

impl<'a> TcpParser<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        let pdu = TcpParser { buffer };
        if buffer.len() < 20 || buffer.len() < pdu.computed_data_offset() {
            return Err(Error::Truncated);
        }
        Ok(pdu)
    }

    pub fn inner(&'a self) -> Result<Tcp<'a>> {
        self.clone().into_inner()
    }

    pub fn into_inner(self) -> Result<Tcp<'a>> {
        let rest = &self.buffer[self.computed_data_offset()..];
        Ok(Tcp::Raw(rest))
    }

    pub fn source_port(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[0..=1].try_into().unwrap())
    }

    pub fn destination_port(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[2..=3].try_into().unwrap())
    }

    pub fn sequence_number(&'a self) -> u32 {
        u32::from_be_bytes(self.buffer[4..=7].try_into().unwrap())
    }

    pub fn acknowledgement_number(&'a self) -> u32 {
        u32::from_be_bytes(self.buffer[8..=11].try_into().unwrap())
    }

    pub fn data_offset(&'a self) -> u8 {
        self.buffer[12] >> 4
    }

    pub fn computed_data_offset(&'a self) -> usize {
        self.data_offset() as usize * 4
    }

    pub fn flags(&'a self) -> u8 {
        self.buffer[13]
    }

    pub fn fin(&'a self) -> bool {
        self.flags() & 0x1 != 0
    }

    pub fn syn(&'a self) -> bool {
        self.flags() & 0x2 != 0
    }

    pub fn rst(&'a self) -> bool {
        self.flags() & 0x4 != 0
    }

    pub fn psh(&'a self) -> bool {
        self.flags() & 0x8 != 0
    }

    pub fn ack(&'a self) -> bool {
        self.flags() & 0x10 != 0
    }

    pub fn urg(&'a self) -> bool {
        self.flags() & 0x20 != 0
    }

    pub fn ecn(&'a self) -> bool {
        self.flags() & 0x40 != 0
    }

    pub fn cwr(&'a self) -> bool {
        self.flags() & 0x80 != 0
    }

    pub fn window_size(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[14..=15].try_into().unwrap())
    }

    pub fn computed_window_size(&'a self, shift: u8) -> u32 {
        (self.window_size() as u32) << (shift as u32)
    }

    pub fn checksum(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[16..=17].try_into().unwrap())
    }

    pub fn computed_checksum(&'a self, ip: &crate::Ip) -> u16 {
        match ip {
            crate::Ip::Ipv4(ipv4) => util::checksum(&[
                &ipv4.source_address().as_ref(),
                &ipv4.destination_address().as_ref(),
                &[0x00, ipv4.protocol()].as_ref(),
                &(ipv4.total_length() as usize - ipv4.computed_ihl())
                    .to_be_bytes()
                    .as_ref(),
                &self.buffer[0..=15],
                &self.buffer[18..],
            ]),
        }
    }

    pub fn urgent_pointer(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[18..=19].try_into().unwrap())
    }

    pub fn options(&'a self) -> TcpOptionIterator<'a> {
        TcpOptionIterator {
            buffer: self.buffer,
            pos: 20,
            data_offset: self.computed_data_offset(),
        }
    }
}

#[derive(Copy, Clone)]
pub enum TcpOption<'a> {
    Raw { option: u8, data: &'a [u8] },
    NoOp,
    Mss { size: u16 },
    WindowScale { shift: u8 },
    SackPermitted,
    Sack { blocks: [Option<(u32, u32)>; 4] },
    Timestamp { val: u32, ecr: u32 },
}

#[derive(Copy, Clone)]
pub struct TcpOptionIterator<'a> {
    buffer: &'a [u8],
    pos: usize,
    data_offset: usize,
}

impl<'a> Iterator for TcpOptionIterator<'a> {
    type Item = TcpOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos < self.data_offset {
            let pos = self.pos;
            let option = self.buffer[pos];
            let len = match option {
                0 | 1 => 1usize,
                _ => {
                    if self.data_offset <= (pos + 1) {
                        return None;
                    }
                    let len = self.buffer[pos + 1] as usize;
                    if len < 2 {
                        return None;
                    }
                    len
                }
            };
            if self.data_offset < (pos + len) {
                return None;
            }
            self.pos += len;
            match option {
                0 => None,
                1 => Some(TcpOption::NoOp),
                2 if len == 4 => Some(TcpOption::Mss {
                    size: u16::from_be_bytes(self.buffer[pos + 2..=pos + 3].try_into().unwrap()),
                }),
                3 if len == 3 => Some(TcpOption::WindowScale {
                    shift: self.buffer[pos + 2],
                }),
                4 => Some(TcpOption::SackPermitted),
                5 if len == 10 => Some(TcpOption::Sack {
                    blocks: [
                        Some((
                            u32::from_be_bytes(self.buffer[pos + 2..=pos + 5].try_into().unwrap()),
                            u32::from_be_bytes(self.buffer[pos + 6..=pos + 9].try_into().unwrap()),
                        )),
                        None,
                        None,
                        None,
                    ],
                }),
                5 if len == 18 => Some(TcpOption::Sack {
                    blocks: [
                        Some((
                            u32::from_be_bytes(self.buffer[pos + 2..=pos + 5].try_into().unwrap()),
                            u32::from_be_bytes(self.buffer[pos + 6..=pos + 9].try_into().unwrap()),
                        )),
                        Some((
                            u32::from_be_bytes(
                                self.buffer[pos + 10..=pos + 13].try_into().unwrap(),
                            ),
                            u32::from_be_bytes(
                                self.buffer[pos + 14..=pos + 17].try_into().unwrap(),
                            ),
                        )),
                        None,
                        None,
                    ],
                }),
                5 if len == 26 => Some(TcpOption::Sack {
                    blocks: [
                        Some((
                            u32::from_be_bytes(self.buffer[pos + 2..=pos + 5].try_into().unwrap()),
                            u32::from_be_bytes(self.buffer[pos + 6..=pos + 9].try_into().unwrap()),
                        )),
                        Some((
                            u32::from_be_bytes(
                                self.buffer[pos + 10..=pos + 13].try_into().unwrap(),
                            ),
                            u32::from_be_bytes(
                                self.buffer[pos + 14..=pos + 17].try_into().unwrap(),
                            ),
                        )),
                        Some((
                            u32::from_be_bytes(
                                self.buffer[pos + 18..=pos + 21].try_into().unwrap(),
                            ),
                            u32::from_be_bytes(
                                self.buffer[pos + 22..=pos + 25].try_into().unwrap(),
                            ),
                        )),
                        None,
                    ],
                }),
                5 if len == 34 => Some(TcpOption::Sack {
                    blocks: [
                        Some((
                            u32::from_be_bytes(self.buffer[pos + 2..=pos + 5].try_into().unwrap()),
                            u32::from_be_bytes(self.buffer[pos + 6..=pos + 9].try_into().unwrap()),
                        )),
                        Some((
                            u32::from_be_bytes(
                                self.buffer[pos + 10..=pos + 13].try_into().unwrap(),
                            ),
                            u32::from_be_bytes(
                                self.buffer[pos + 14..=pos + 17].try_into().unwrap(),
                            ),
                        )),
                        Some((
                            u32::from_be_bytes(
                                self.buffer[pos + 18..=pos + 21].try_into().unwrap(),
                            ),
                            u32::from_be_bytes(
                                self.buffer[pos + 22..=pos + 25].try_into().unwrap(),
                            ),
                        )),
                        Some((
                            u32::from_be_bytes(
                                self.buffer[pos + 26..=pos + 29].try_into().unwrap(),
                            ),
                            u32::from_be_bytes(
                                self.buffer[pos + 30..=pos + 33].try_into().unwrap(),
                            ),
                        )),
                    ],
                }),
                8 if len == 10 => Some(TcpOption::Timestamp {
                    val: u32::from_be_bytes(self.buffer[pos + 2..=pos + 5].try_into().unwrap()),
                    ecr: u32::from_be_bytes(self.buffer[pos + 6..=pos + 9].try_into().unwrap()),
                }),
                _ => Some(TcpOption::Raw {
                    option,
                    data: &self.buffer[pos..(pos + len)],
                }),
            }
        } else {
            None
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}
