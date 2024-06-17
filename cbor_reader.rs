use std::convert::TryInto;

#[derive(Debug, Clone, Copy)]
enum CborReadResult {
    Ok,
    End,
    Malformed,
    NotFound,
}

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

struct CborIn<'a> {
    buffer: &'a [u8],
    cursor: usize,
}

impl<'a> CborIn<'a> {
    fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, cursor: 0 }
    }

    fn offset(&self) -> usize {
        self.cursor
    }

    fn at_end(&self) -> bool {
        self.cursor == self.buffer.len()
    }

    fn would_overflow(&self, size: usize) -> bool {
        size > usize::MAX - self.cursor || self.cursor + size > self.buffer.len()
    }

    fn peek_initial_value_and_argument(&mut self) -> Result<(u8, CborType, u64), CborReadResult> {
        if self.at_end() {
            return Err(CborReadResult::End);
        }
        let initial_byte = self.buffer[self.cursor];
        let cbor_type = match initial_byte >> 5 {
            0 => CborType::Uint,
            1 => CborType::Nint,
            2 => CborType::Bstr,
            3 => CborType::Tstr,
            4 => CborType::Array,
            5 => CborType::Map,
            6 => CborType::Tag,
            7 => CborType::Simple,
            _ => return Err(CborReadResult::Malformed),
        };
        let additional_information = initial_byte & 0x1f;
        let mut value = additional_information as u64;
        let mut bytes = 1;

        if additional_information > 23 {
            bytes += match additional_information {
                24 => 1,
                25 => 2,
                26 => 4,
                27 => 8,
                _ => return Err(CborReadResult::Malformed),
            };
            if self.would_overflow(bytes) {
                return Err(CborReadResult::End);
            }
            value = 0;
            for i in 1..bytes {
                value = (value << 8) | self.buffer[self.cursor + i] as u64;
            }
        }
        Ok((bytes, cbor_type, value))
    }

    fn read_size(&mut self, expected_type: CborType) -> Result<usize, CborReadResult> {
        let (bytes, cbor_type, raw_value) = self.peek_initial_value_and_argument()?;
        if cbor_type != expected_type {
            return Err(CborReadResult::NotFound);
        }
        if raw_value > usize::MAX as u64 {
            return Err(CborReadResult::Malformed);
        }
        self.cursor += bytes;
        Ok(raw_value as usize)
    }

    fn read_str(&mut self, expected_type: CborType) -> Result<&'a [u8], CborReadResult> {
        let size = self.read_size(expected_type)?;
        if self.would_overflow(size) {
            return Err(CborReadResult::End);
        }
        let result = &self.buffer[self.cursor..self.cursor + size];
        self.cursor += size;
        Ok(result)
    }

    fn read_simple(&mut self, expected_val: u8) -> Result<(), CborReadResult> {
        let (bytes, cbor_type, raw_value) = self.peek_initial_value_and_argument()?;
        if cbor_type != CborType::Simple || raw_value != expected_val as u64 {
            return Err(CborReadResult::NotFound);
        }
        self.cursor += bytes;
        Ok(())
    }

    fn read_int(&mut self) -> Result<i64, CborReadResult> {
        let (bytes, cbor_type, raw_value) = self.peek_initial_value_and_argument()?;
        if cbor_type != CborType::Uint && cbor_type != CborType::Nint {
            return Err(CborReadResult::NotFound);
        }
        if raw_value > i64::MAX as u64 {
            return Err(CborReadResult::Malformed);
        }
        self.cursor += bytes;
        Ok(if cbor_type == CborType::Nint {
            -1 - raw_value as i64
        } else {
            raw_value as i64
        })
    }

    fn read_uint(&mut self) -> Result<u64, CborReadResult> {
        let (bytes, cbor_type, raw_value) = self.peek_initial_value_and_argument()?;
        if cbor_type != CborType::Uint {
            return Err(CborReadResult::NotFound);
        }
        self.cursor += bytes;
        Ok(raw_value)
    }

    fn read_bstr(&mut self) -> Result<&'a [u8], CborReadResult> {
        self.read_str(CborType::Bstr)
    }

    fn read_tstr(&mut self) -> Result<&'a [u8], CborReadResult> {
        self.read_str(CborType::Tstr)
    }

    fn read_array(&mut self) -> Result<usize, CborReadResult> {
        self.read_size(CborType::Array)
    }

    fn read_map(&mut self) -> Result<usize, CborReadResult> {
        self.read_size(CborType::Map)
    }

    fn read_tag(&mut self) -> Result<u64, CborReadResult> {
        let (bytes, cbor_type, tag) = self.peek_initial_value_and_argument()?;
        if cbor_type != CborType::Tag {
            return Err(CborReadResult::NotFound);
        }
        self.cursor += bytes;
        Ok(tag)
    }

    fn read_false(&mut self) -> Result<(), CborReadResult> {
        self.read_simple(20)
    }

    fn read_true(&mut self) -> Result<(), CborReadResult> {
        self.read_simple(21)
    }

    fn read_null(&mut self) -> Result<(), CborReadResult> {
        self.read_simple(22)
    }

    fn read_skip(&mut self) -> Result<(), CborReadResult> {
        let mut peeker = *self;
        let mut size_stack = vec![1];

        while let Some(top) = size_stack.last_mut() {
            let (bytes, cbor_type, val) = peeker.peek_initial_value_and_argument()?;
            if peeker.would_overflow(bytes) {
                return Err(CborReadResult::End);
            }
            peeker.cursor += bytes;
            *top -= 1;
            if *top == 0 {
                size_stack.pop();
            }

            match cbor_type {
                CborType::Uint | CborType::Nint | CborType::Simple => {}
                CborType::Bstr | CborType::Tstr => {
                    if peeker.would_overflow(val as usize) {
                        return Err(CborReadResult::End);
                    }
                    peeker.cursor += val as usize;
                }
                CborType::Map => {
                    if val > (usize::MAX / 2) as u64 {
                        return Err(CborReadResult::End);
                    }
                    size_stack.push((val * 2) as usize);
                }
                CborType::Tag => {
                    size_stack.push(1);
                }
                CborType::Array => {
                    size_stack.push(val as usize);
                }
                _ => return Err(CborReadResult::Malformed),
            }
        }

        self.cursor = peeker.cursor;
        Ok(())
    }
}

fn main() {
    let buffer = vec![0u8; 1024];
    let mut cbor_in = CborIn::new(&buffer);

    match cbor_in.read_int() {
        Ok(val) => println!("Read Int: {}", val),
        Err(err) => println!("Error reading int: {:?}", err),
    }
    // 다른 읽기 함수들도 유사하게 사용할 수 있습니다.
}
