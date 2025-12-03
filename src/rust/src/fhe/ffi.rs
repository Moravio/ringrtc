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

#[link(name = "FHE_Rust")]
unsafe extern "C" {
    fn createCryptoContext();

    #[link_name = "encrypt"]
    fn _encrypt(input_ptr: *const f32, len: usize) -> ByteBuffer;

    #[link_name = "decrypt"]
    fn _decrypt(data_ptr: *const u8, len: usize) -> FloatBuffer;
    
    fn freeByteBuffer(ptr: *mut u8, len: usize);
    fn freeFloatBuffer(ptr: *mut f32, len: usize);
}

pub fn create_crypto_context() {
    unsafe { createCryptoContext() };
}

pub fn encrypt(input: &[f32]) -> Vec<u8> {
    info!("encrypting data of size {}", input.len());
    unsafe {
        let buf = _encrypt(input.as_ptr(), input.len());
        if buf.ptr.is_null() || buf.len == 0 {
            info!("failed to encrypt data");

            return Vec::new();
        }
        let slice = std::slice::from_raw_parts(buf.ptr, buf.len);
        let out = slice.to_vec();

        info!("encrypted data of size {}", out.len());

        freeByteBuffer(buf.ptr, buf.len);
        out
    }
}

pub fn decrypt(data: &[u8]) -> Vec<f32> {
    unsafe {
        let buf = _decrypt(data.as_ptr(), data.len());
        if buf.ptr.is_null() || buf.len == 0 {
            return Vec::new();
        }
        let slice = std::slice::from_raw_parts(buf.ptr, buf.len);
        let out = slice.to_vec();
        freeFloatBuffer(buf.ptr, buf.len);
        out
    }
}
