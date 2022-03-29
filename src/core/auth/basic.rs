use crate::core::utils::{encode_base64_len, encode_base64};

pub fn basic_compute_response(username: &str, password: &str) -> String {
    let mut ret = String::with_capacity(encode_base64_len(username.len() + password.len() + 1));
    let s = format!("{}:{}", username, password);
    unsafe {
        encode_base64(s.as_bytes(), ret.as_bytes_mut());
    }

    return ret;    
}