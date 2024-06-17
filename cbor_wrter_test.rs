#[cfg(test)]
mod tests {
    use ciborium::ser::into_writer;
    use ciborium::value::Value;
    use std::io::Cursor;

    #[test]
    fn int_1_byte_encoding() {
        let expected_encoding = [0, 23, 0x20, 0x37];
        let mut buffer = Vec::new();

        into_writer(&Value::Integer(0.into()), &mut buffer).unwrap();
        into_writer(&Value::Integer(23.into()), &mut buffer).unwrap();
        into_writer(&Value::Integer((-1).into()), &mut buffer).unwrap();
        into_writer(&Value::Integer((-24).into()), &mut buffer).unwrap();

        assert_eq!(buffer, expected_encoding);
    }

    #[test]
    fn int_2_bytes() {
        let expected_encoding = [24, 24, 24, 0xff, 0x38, 24, 0x38, 0xff];
        let mut buffer = Vec::new();

        into_writer(&Value::Integer(24.into()), &mut buffer).unwrap();
        into_writer(&Value::Integer(0xff.into()), &mut buffer).unwrap();
        into_writer(&Value::Integer((-25).into()), &mut buffer).unwrap();
        into_writer(&Value::Integer((-0x100).into()), &mut buffer).unwrap();

        assert_eq!(buffer, expected_encoding);
    }

    #[test]
    fn int_3_bytes() {
        let expected_encoding = [25, 0x01, 0x00, 25, 0xff, 0xff, 0x39, 0x01, 0x00, 0x39, 0xff, 0xff];
        let mut buffer = Vec::new();

        into_writer(&Value::Integer(0x100.into()), &mut buffer).unwrap();
        into_writer(&Value::Integer(0xffff.into()), &mut buffer).unwrap();
        into_writer(&Value::Integer((-0x101).into()), &mut buffer).unwrap();
        into_writer(&Value::Integer((-0x10000).into()), &mut buffer).unwrap();

        assert_eq!(buffer, expected_encoding);
    }

    #[test]
    fn int_5_bytes() {
        let expected_encoding = [26, 0x00, 0x01, 0x00, 0x00, 26, 0xff, 0xff, 0xff, 0xff, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x3a, 0xff, 0xff, 0xff, 0xff];
        let mut buffer = Vec::new();

        into_writer(&Value::Integer(0x10000.into()), &mut buffer).unwrap();
        into_writer(&Value::Integer(0xffffffff.into()), &mut buffer).unwrap();
        into_writer(&Value::Integer((-0x10001).into()), &mut buffer).unwrap();
        into_writer(&Value::Integer((-0x100000000).into()), &mut buffer).unwrap();

        assert_eq!(buffer, expected_encoding);
    }

    #[test]
    fn int_9_bytes() {
        let expected_encoding = [27, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 27, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let mut buffer = Vec::new();

        into_writer(&Value::Integer(0x100000000.into()), &mut buffer).unwrap();
        into_writer(&Value::Integer(i64::MAX.into()), &mut buffer).unwrap();
        into_writer(&Value::Integer((-0x100000001).into()), &mut buffer).unwrap();
        into_writer(&Value::Integer(i64::MIN.into()), &mut buffer).unwrap();

        assert_eq!(buffer, expected_encoding);
    }

    #[test]
    fn uint_9_bytes() {
        let expected_encoding = [27, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 27, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let mut buffer = Vec::new();

        into_writer(&Value::Integer(0x100000000.into()), &mut buffer).unwrap();
        into_writer(&Value::Integer(u64::MAX.into()), &mut buffer).unwrap();

        assert_eq!(buffer, expected_encoding);
    }

    #[test]
    fn int_byte_order() {
        let expected_encoding = [25, 0x12, 0x34, 26, 0x12, 0x34, 0x56, 0x78, 27, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let mut buffer = Vec::new();

        into_writer(&Value::Integer(0x1234.into()), &mut buffer).unwrap();
        into_writer(&Value::Integer(0x12345678.into()), &mut buffer).unwrap();
        into_writer(&Value::Integer(0x123456789abcdef0.into()), &mut buffer).unwrap();

        assert_eq!(buffer, expected_encoding);
    }

    #[test]
    fn bstr_encoding() {
        let expected_encoding = [0x45, b'h', b'e', b'l', b'l', b'o'];
        let data = [b'h', b'e', b'l', b'l', b'o'];
        let mut buffer = Vec::new();

        into_writer(&Value::Bytes(data.to_vec()), &mut buffer).unwrap();

        assert_eq!(buffer, expected_encoding);
    }

    #[test]
    fn bstr_alloc_encoding() {
        let expected_encoding = [0x45, b'a', b'l', b'l', b'o', b'c'];
        let data = [b'a', b'l', b'l', b'o', b'c'];
        let mut buffer = Vec::new();

        into_writer(&Value::Bytes(data.to_vec()), &mut buffer).unwrap();

        assert_eq!(buffer, expected_encoding);
    }

    #[test]
    fn tstr_encoding() {
        let expected_encoding = [0x65, b'w', b'o', b'r', b'l', b'd'];
        let mut buffer = Vec::new();

        into_writer(&Value::Text("world".to_string()), &mut buffer).unwrap();

        assert_eq!(buffer, expected_encoding);
    }

    #[test]
    fn tstr_alloc_encoding() {
        let expected_encoding = [0x65, b's', b'p', b'a', b'c', b'e'];
        let data = "space";
        let mut buffer = Vec::new();

        into_writer(&Value::Text(data.to_string()), &mut buffer).unwrap();

        assert_eq!(buffer, expected_encoding);
    }

    #[test]
    fn array_encoding() {
        let expected_encoding = [0x98, 29];
        let mut buffer = Vec::new();

        into_writer(&Value::Array(vec![Value::Integer(1.into()); 29]), &mut buffer).unwrap();

        assert_eq!(buffer, expected_encoding);
    }

    #[test]
    fn map_encoding() {
        let expected_encoding = [0xb9, 0x02, 0x50];
        let mut buffer = Vec::new();

        let mut map = std::collections::BTreeMap::new();
        for i in 0..592 {
            map.insert(Value::Integer(i.into()), Value::Integer(i.into()));
        }

        into_writer(&Value::Map(map), &mut buffer).unwrap();

        assert_eq!(buffer, expected_encoding);
    }

    #[test]
    fn tag_encoding() {
        let expected_encoding = [0xcf, 0xd8, 0x18, 0xd9, 0xd9, 0xf8, 0xda, 0x4f, 0x50, 0x53, 0x4e, 0xdb, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut buffer = Vec::new();

        into_writer(&Value::Tag(15.into(), Box::new(Value::Integer(0.into()))), &mut buffer).unwrap();
        into_writer(&Value::Tag(24.into(), Box::new(Value::Integer(0.into()))), &mut buffer).unwrap();
        into_writer(&Value::Tag(25.into(), Box::new(Value::Integer(0.into()))), &mut buffer).unwrap();
        into_writer(&Value::Tag(32.into(), Box::new(Value::Integer(0.into()))), &mut buffer).unwrap();
        into_writer(&Value::Tag(255.into(), Box::new(Value::Integer(0.into()))), &mut buffer).unwrap();

        assert_eq!(buffer, expected_encoding);
    }

    #[test]
    fn floating_point_encoding() {
        let expected_encoding = [0xfa, 0x3f, 0x99, 0x99, 0x9a, 0xfb, 0x3f, 0xf3, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33];
        let mut buffer = Vec::new();

        into_writer(&Value::Float(1.2), &mut buffer).unwrap();
        into_writer(&Value::Float(1.2), &mut buffer).unwrap();

        assert_eq!(buffer, expected_encoding);
    }

    #[test]
    fn floating_point_infinity() {
        let expected_encoding = [0xf9, 0x7c, 0x00, 0xf9, 0x7e, 0x00];
        let mut buffer = Vec::new();

        into_writer(&Value::Float(f64::INFINITY), &mut buffer).unwrap();
        into_writer(&Value::Float(f64::NAN), &mut buffer).unwrap();

        assert_eq!(buffer, expected_encoding);
    }
}
