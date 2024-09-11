use base64::{engine::general_purpose, Engine};

pub fn encode<T: AsRef<[u8]>>(input: T) -> String {
    general_purpose::STANDARD.encode(input)
}

pub fn decode_vec(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let mut buffer = Vec::<u8>::new();
    general_purpose::STANDARD.decode_vec(input, &mut buffer)?;
    Ok(buffer)
}

pub fn decode_slice_32(input: &str) -> Result<[u8; 32], base64::DecodeSliceError> {
    let mut buffer = [0u8; 32];
    general_purpose::STANDARD.decode_slice(input, &mut buffer)?;
    Ok(buffer)
}
