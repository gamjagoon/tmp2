use std::convert::TryInto;

#[derive(Debug, Clone, Copy)]
enum CborType {
    Uint = 0,
    Nint = 1,
    Bstr = 2,
    Tstr = 3,
    Array = 4,
    Map = 5,
    Tag = 6,
    Simple = 7,
}

struct CborOut<'a> {
    buffer: &'a mut [u8],
    cursor: usize,
}

impl<'a> CborOut<'a> {
    fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, cursor: 0 }
    }

    fn would_overflow(&self, size: usize) -> bool {
        size > self.buffer.len().saturating_sub(self.cursor)
    }

    fn fits_in_buffer(&self, size: usize) -> bool {
        self.cursor <= self.buffer.len() && size <= self.buffer.len().saturating_sub(self.cursor)
    }

    fn write_type(&mut self, cbor_type: CborType, val: u64) {
        let size = match val {
            0..=23 => 1,
            24..=0xff => 2,
            0x100..=0xffff => 3,
            0x10000..=0xffffffff => 5,
            _ => 9,
        };

        if self.would_overflow(size) {
            self.cursor = usize::MAX;
            return;
        }

        if self.fits_in_buffer(size) {
            match size {
                1 => self.buffer[self.cursor] = (cbor_type as u8) << 5 | val as u8,
                2 => {
                    self.buffer[self.cursor] = (cbor_type as u8) << 5 | 24;
                    self.buffer[self.cursor + 1] = val as u8;
                }
                3 => {
                    self.buffer[self.cursor] = (cbor_type as u8) << 5 | 25;
                    self.buffer[self.cursor + 1] = (val >> 8) as u8;
                    self.buffer[self.cursor + 2] = val as u8;
                }
                5 => {
                    self.buffer[self.cursor] = (cbor_type as u8) << 5 | 26;
                    self.buffer[self.cursor + 1] = (val >> 24) as u8;
                    self.buffer[self.cursor + 2] = (val >> 16) as u8;
                    self.buffer[self.cursor + 3] = (val >> 8) as u8;
                    self.buffer[self.cursor + 4] = val as u8;
                }
                9 => {
                    self.buffer[self.cursor] = (cbor_type as u8) << 5 | 27;
                    self.buffer[self.cursor + 1] = (val >> 56) as u8;
                    self.buffer[self.cursor + 2] = (val >> 48) as u8;
                    self.buffer[self.cursor + 3] = (val >> 40) as u8;
                    self.buffer[self.cursor + 4] = (val >> 32) as u8;
                    self.buffer[self.cursor + 5] = (val >> 24) as u8;
                    self.buffer[self.cursor + 6] = (val >> 16) as u8;
                    self.buffer[self.cursor + 7] = (val >> 8) as u8;
                    self.buffer[self.cursor + 8] = val as u8;
                }
                _ => {}
            }
        }

        self.cursor += size;
    }

    fn alloc_str(&mut self, cbor_type: CborType, data_size: usize) -> Option<&mut [u8]> {
        self.write_type(cbor_type, data_size as u64);
        if self.would_overflow(data_size) || !self.fits_in_buffer(data_size) {
            None
        } else {
            let start = self.cursor;
            self.cursor += data_size;
            Some(&mut self.buffer[start..self.cursor])
        }
    }

    fn write_str(&mut self, cbor_type: CborType, data: &[u8]) {
        if let Some(ptr) = self.alloc_str(cbor_type, data.len()) {
            ptr.copy_from_slice(data);
        }
    }

    fn write_int(&mut self, val: i64) {
        if val < 0 {
            self.write_type(CborType::Nint, (-1 - val) as u64);
        } else {
            self.write_type(CborType::Uint, val as u64);
        }
    }

    fn write_uint(&mut self, val: u64) {
        self.write_type(CborType::Uint, val);
    }

    fn write_bstr(&mut self, data: &[u8]) {
        self.write_str(CborType::Bstr, data);
    }

    fn alloc_bstr(&mut self, data_size: usize) -> Option<&mut [u8]> {
        self.alloc_str(CborType::Bstr, data_size)
    }

    fn write_tstr(&mut self, data: &str) {
        self.write_str(CborType::Tstr, data.as_bytes());
    }

    fn alloc_tstr(&mut self, size: usize) -> Option<&mut [u8]> {
        self.alloc_str(CborType::Tstr, size)
    }

    fn write_array(&mut self, num_elements: usize) {
        self.write_type(CborType::Array, num_elements as u64);
    }

    fn write_map(&mut self, num_pairs: usize) {
        self.write_type(CborType::Map, num_pairs as u64);
    }

    fn write_tag(&mut self, tag: u64) {
        self.write_type(CborType::Tag, tag);
    }

    fn write_false(&mut self) {
        self.write_type(CborType::Simple, 20);
    }

    fn write_true(&mut self) {
        self.write_type(CborType::Simple, 21);
    }

    fn write_null(&mut self) {
        self.write_type(CborType::Simple, 22);
    }

    fn size(&self) -> usize {
        self.cursor
    }

    fn overflowed(&self) -> bool {
        self.cursor == usize::MAX || self.cursor > self.buffer.len()
    }
}

fn main() {
    let mut buffer = vec![0u8; 1024];
    let mut cbor_out = CborOut::new(&mut buffer);

    cbor_out.write_int(42);
    cbor_out.write_int(-42);
    cbor_out.write_tstr("Hello, CBOR!");
    cbor_out.write_array(2);
    cbor_out.write_uint(12345);
    cbor_out.write_false();

    println!("CBOR Output Size: {}", cbor_out.size());
    println!("CBOR Overflowed: {}", cbor_out.overflowed());
    println!("CBOR Output: {:?}", &buffer[..cbor_out.size()]);
}
