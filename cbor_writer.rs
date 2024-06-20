use std::mem::size_of;

const K_COSE_KEY_KTY_LABEL: i64 = 1;
const K_COSE_KEY_ALG_LABEL: i64 = 3;
const K_COSE_KEY_OPS_LABEL: i64 = 4;
const K_COSE_OKP_CRV_LABEL: i64 = -1;
const K_COSE_OKP_X_LABEL: i64 = -2;
const K_COSE_KEY_TYPE_OKP: i64 = 1;
const K_COSE_ALG_EDDSA: i64 = 6; // Placeholder for DICE_COSE_KEY_ALG_VALUE
const K_COSE_KEY_OPS_VERIFY: i64 = 2;
const K_COSE_CRV_ED25519: i64 = 6;
const DICE_PUBLIC_KEY_SIZE: usize = 32; // Placeholder for the size of the public key

// Result codes
const K_DICE_RESULT_OK: i32 = 0;
const K_DICE_RESULT_BUFFER_TOO_SMALL: i32 = 1;

struct CborOut {
    buffer: Vec<u8>,
    cursor: usize,
}

impl CborOut {
    fn new(buffer_size: usize) -> Self {
        CborOut {
            buffer: vec![0u8; buffer_size],
            cursor: 0,
        }
    }

    fn size(&self) -> usize {
        self.cursor
    }

    fn overflowed(&self) -> bool {
        self.cursor == usize::MAX || self.cursor > self.buffer.len()
    }

    fn write_type(&mut self, type_: u8, val: u64) {
        let size = if val <= 23 {
            1
        } else if val <= 0xff {
            2
        } else if val <= 0xffff {
            3
        } else if val <= 0xffffffff {
            5
        } else {
            9
        };

        if self.cursor + size > self.buffer.len() {
            self.cursor = usize::MAX;
            return;
        }

        if size == 1 {
            self.buffer[self.cursor] = (type_ << 5) | (val as u8);
        } else if size == 2 {
            self.buffer[self.cursor..self.cursor + 2].copy_from_slice(&[
                (type_ << 5) | 24,
                val as u8,
            ]);
        } else if size == 3 {
            self.buffer[self.cursor..self.cursor + 3].copy_from_slice(&[
                (type_ << 5) | 25,
                (val >> 8) as u8,
                val as u8,
            ]);
        } else if size == 5 {
            self.buffer[self.cursor..self.cursor + 5].copy_from_slice(&[
                (type_ << 5) | 26,
                (val >> 24) as u8,
                (val >> 16) as u8,
                (val >> 8) as u8,
                val as u8,
            ]);
        } else if size == 9 {
            self.buffer[self.cursor..self.cursor + 9].copy_from_slice(&[
                (type_ << 5) | 27,
                (val >> 56) as u8,
                (val >> 48) as u8,
                (val >> 40) as u8,
                (val >> 32) as u8,
                (val >> 24) as u8,
                (val >> 16) as u8,
                (val >> 8) as u8,
                val as u8,
            ]);
        }

        self.cursor += size;
    }

    fn alloc_str(&mut self, type_: u8, data_size: usize) -> Option<&mut [u8]> {
        self.write_type(type_, data_size as u64);
        if self.cursor == usize::MAX || self.cursor + data_size > self.buffer.len() {
            None
        } else {
            let start = self.cursor;
            self.cursor += data_size;
            Some(&mut self.buffer[start..start + data_size])
        }
    }

    fn write_str(&mut self, type_: u8, data: &[u8]) {
        if let Some(ptr) = self.alloc_str(type_, data.len()) {
            ptr.copy_from_slice(data);
        }
    }

    fn write_int(&mut self, val: i64) {
        if val < 0 {
            self.write_type(1, (-1 - val) as u64);
        } else {
            self.write_type(0, val as u64);
        }
    }

    fn write_uint(&mut self, val: u64) {
        self.write_type(0, val);
    }

    fn write_bstr(&mut self, data: &[u8]) {
        self.write_str(2, data);
    }

    fn write_tstr(&mut self, string: &str) {
        self.write_str(3, string.as_bytes());
    }

    fn write_array(&mut self, num_elements: usize) {
        self.write_type(4, num_elements as u64);
    }

    fn write_map(&mut self, num_pairs: usize) {
        self.write_type(5, num_pairs as u64);
    }

    fn write_tag(&mut self, tag: u64) {
        self.write_type(6, tag);
    }

    fn write_false(&mut self) {
        self.write_type(7, 20);
    }

    fn write_true(&mut self) {
        self.write_type(7, 21);
    }

    fn write_null(&mut self) {
        self.write_type(7, 22);
    }
}

fn dice_cose_encode_public_key(
    context_not_used: *mut u8,
    public_key: &[u8; DICE_PUBLIC_KEY_SIZE],
    buffer_size: usize,
    buffer: &mut [u8],
    encoded_size: &mut usize,
) -> i32 {
    // Initialize CBOR output
    let mut cbor_out = CborOut::new(buffer_size);

    // Add the map with 5 pairs
    cbor_out.write_map(5);

    // Add the key type
    cbor_out.write_int(K_COSE_KEY_KTY_LABEL);
    cbor_out.write_int(K_COSE_KEY_TYPE_OKP);

    // Add the algorithm
    cbor_out.write_int(K_COSE_KEY_ALG_LABEL);
    cbor_out.write_int(K_COSE_ALG_EDDSA);

    // Add the KeyOps
    cbor_out.write_int(K_COSE_KEY_OPS_LABEL);
    cbor_out.write_array(1);
    cbor_out.write_int(K_COSE_KEY_OPS_VERIFY);

    // Add the curve
    cbor_out.write_int(K_COSE_OKP_CRV_LABEL);
    cbor_out.write_int(K_COSE_CRV_ED25519);

    // Add the public key
    cbor_out.write_int(K_COSE_OKP_X_LABEL);
    cbor_out.write_bstr(public_key);

    // Set the encoded size
    *encoded_size = cbor_out.size();

    // Check for overflow
    if cbor_out.overflowed() {
        return K_DICE_RESULT_BUFFER_TOO_SMALL;
    } else {
        buffer[..*encoded_size].copy_from_slice(&cbor_out.buffer[..*encoded_size]);
        return K_DICE_RESULT_OK;
    }
}

fn main() {
    let public_key: [u8; DICE_PUBLIC_KEY_SIZE] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                                  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                                                  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                                                  0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];
    let buffer_size = 128;
    let mut buffer = vec![0u8; buffer_size];
    let mut encoded_size = 0;

    let result = dice_cose_encode_public_key(std::ptr::null_mut(), &public_key, buffer_size, &mut buffer, &mut encoded_size);

    println!("Result: {}", result);
    println!("Encoded size: {}", encoded_size);
    println!("Buffer: {:?}", &buffer[..encoded_size]);
}
