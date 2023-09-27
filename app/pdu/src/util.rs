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
