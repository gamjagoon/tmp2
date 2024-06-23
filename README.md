error[E0599]: no method named `bytes_len` found for struct `Encoder` in the current scope
   --> src\main.rs:177:9
    |
177 |     enc.bytes_len(payload_size).unwrap();
    |         ^^^^^^^^^ help: there is a method with a similar name: `bytes`

