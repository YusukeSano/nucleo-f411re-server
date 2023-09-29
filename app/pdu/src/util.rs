use core::convert::TryInto;

pub fn checksum<I, J>(spans: I) -> u16
where
    I: IntoIterator<Item = J>,
    J: AsRef<[u8]>,
{
    let mut accum = 0u32;

    for span in spans.into_iter() {
        accum += sum(span.as_ref()) as u32;
    }

    accum = (accum >> 16) + (accum & 0xffff);
    !(((accum >> 16) as u16) + (accum as u16))
}

fn sum(mut buffer: &[u8]) -> u16 {
    let mut accum = 0;

    while buffer.len() >= 32 {
        let mut b = &buffer[..32];
        while b.len() >= 2 {
            accum += u16::from_be_bytes(b[0..=1].try_into().unwrap()) as u32;
            b = &b[2..];
        }
        buffer = &buffer[32..];
    }

    while buffer.len() >= 2 {
        accum += u16::from_be_bytes(buffer[0..=1].try_into().unwrap()) as u32;
        buffer = &buffer[2..];
    }

    if let Some(&value) = buffer.first() {
        accum += (value as u32) << 8;
    }

    accum = (accum >> 16) + (accum & 0xffff);
    ((accum >> 16) as u16) + (accum as u16)
}

pub fn crc32(data: &[u8]) -> u32 {
    const CRC32_POLY: u32 = 0xEDB88320;
    let mut crc: u32 = 0xFFFFFFFF;

    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ CRC32_POLY;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

pub struct Xorshift32 {
    state: u32,
}

impl Xorshift32 {
    pub fn new(seed: u32) -> Xorshift32 {
        Xorshift32 { state: seed }
    }

    pub fn gen(&mut self) -> u32 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 17;
        self.state ^= self.state << 5;
        self.state
    }
}

pub fn get_digit_from_usize(val: usize) -> u8 {
    let mut num = val;
    let mut digit = 0;
    while num != 0 {
        num /= 10;
        digit += 1;
    }
    digit
}

pub fn usize_to_bytes(val: usize) -> [u8; 4] {
    let mut ans = [0u8; 4];
    for i in (0..4).rev() {
        let digit_num = (val as u32) % 10u32.pow(i + 1) / 10u32.pow(i);
        let chr = core::char::from_digit(digit_num, 10).unwrap();
        ans[3 - i as usize] = chr as u8;
    }
    ans
}
