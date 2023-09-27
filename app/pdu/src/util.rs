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
