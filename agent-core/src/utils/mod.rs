/// Helper function to convert C string to Rust string
pub fn cstr_to_string(cstr: &[i8]) -> String {
    let mut bytes = Vec::new();
    for &c in cstr {
        if c == 0 {
            break;
        }
        bytes.push(c as u8);
    }
    String::from_utf8_lossy(&bytes).to_string()
}
