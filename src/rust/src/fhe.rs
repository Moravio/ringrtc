#[repr(C)]
pub struct ByteBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

#[repr(C)]
pub struct FloatBuffer {
    pub ptr: *mut f32,
    pub len: usize,
}

#[repr(C)]
pub struct KeyPair {
    pub public_key: ByteBuffer,
    pub secret_key: ByteBuffer,
}

#[link(name = "ringrtc_fhe")]
unsafe extern "C" {
    fn createCryptoContext();
    fn generateKeys(secret_ptr: *const u8, len: usize) -> KeyPair;

    #[link_name = "encrypt"]
    fn _encrypt(
        input_ptr: *const f32, 
        len: usize, 
        pub_key_ptr: *const u8, 
        pub_key_len: usize
    ) -> ByteBuffer;

    #[link_name = "decrypt"]
    fn _decrypt(
        data_ptr: *const u8, 
        len: usize, 
        secret_key_ptr: *const u8, 
        secret_key_len: usize
    ) -> FloatBuffer;
    
    fn freeByteBuffer(ptr: *mut u8);
    fn freeFloatBuffer(ptr: *mut f32);
    fn freeKeyPair(keys: KeyPair);
}

pub fn generate_keys(#[allow(unused)] current_secret: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    unsafe {
        createCryptoContext();

        let key_pair = generateKeys(current_secret.as_ptr(), current_secret.len());
        
        let pub_key = if key_pair.public_key.ptr.is_null() || key_pair.public_key.len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(key_pair.public_key.ptr, key_pair.public_key.len).to_vec()
        };

        let sec_key = if key_pair.secret_key.ptr.is_null() || key_pair.secret_key.len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(key_pair.secret_key.ptr, key_pair.secret_key.len).to_vec()
        };

        freeKeyPair(key_pair);

        (pub_key, sec_key)
    }
}

pub fn encrypt(input: &[f32], public_key: &[u8]) -> Vec<u8> {
    unsafe {
        let buf = _encrypt(input.as_ptr(), input.len(), public_key.as_ptr(), public_key.len());
        if buf.ptr.is_null() || buf.len == 0 {
            return Vec::new();
        }
        let slice = std::slice::from_raw_parts(buf.ptr, buf.len);
        let out = slice.to_vec();

        freeByteBuffer(buf.ptr);

        out
    }
}

pub fn decrypt(data: &[u8], secret_key: &[u8]) -> Vec<f32> {
    unsafe {
        let buf = _decrypt(data.as_ptr(), data.len(), secret_key.as_ptr(), secret_key.len());
        if buf.ptr.is_null() || buf.len == 0 {
            return Vec::new();
        }
        let slice = std::slice::from_raw_parts(buf.ptr, buf.len);
        let out = slice.to_vec();
        
        freeFloatBuffer(buf.ptr);
        
        out
    }
}
