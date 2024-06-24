fn hex_encode(input: &[u8], output: &mut [u8]) {
    const HEX_MAP: &[u8; 16] = b"0123456789abcdef";
    for (i, &byte) in input.iter().enumerate() {
        output[i * 2] = HEX_MAP[(byte >> 4) as usize];
        output[i * 2 + 1] = HEX_MAP[(byte & 0xf) as usize];
    }
}
