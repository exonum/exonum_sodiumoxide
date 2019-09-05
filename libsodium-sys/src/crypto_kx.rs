pub const crypto_kx_PUBLICKEYBYTES: u32 = 32;
pub const crypto_kx_SECRETKEYBYTES: u32 = 32;
pub const crypto_kx_SEEDBYTES: u32 = 32;
pub const crypto_kx_SESSIONKEYBYTES: u32 = 32;
pub const crypto_kx_PRIMITIVE: &[u8; 14usize] = b"x25519blake2b\0";

extern "C" {
    pub fn crypto_kdf_keygen(k: *mut libc::c_uchar);
}
extern "C" {
    pub fn crypto_kx_publickeybytes() -> usize;
}
extern "C" {
    pub fn crypto_kx_secretkeybytes() -> usize;
}
extern "C" {
    pub fn crypto_kx_seedbytes() -> usize;
}
extern "C" {
    pub fn crypto_kx_sessionkeybytes() -> usize;
}
extern "C" {
    pub fn crypto_kx_primitive() -> *const libc::c_char;
}
extern "C" {
    pub fn crypto_kx_seed_keypair(
        pk: *mut libc::c_uchar,
        sk: *mut libc::c_uchar,
        seed: *const libc::c_uchar,
    ) -> libc::c_int;
}
extern "C" {
    pub fn crypto_kx_keypair(pk: *mut libc::c_uchar, sk: *mut libc::c_uchar) -> libc::c_int;
}
extern "C" {
    pub fn crypto_kx_client_session_keys(
        rx: *mut libc::c_uchar,
        tx: *mut libc::c_uchar,
        client_pk: *const libc::c_uchar,
        client_sk: *const libc::c_uchar,
        server_pk: *const libc::c_uchar,
    ) -> libc::c_int;
}
extern "C" {
    pub fn crypto_kx_server_session_keys(
        rx: *mut libc::c_uchar,
        tx: *mut libc::c_uchar,
        server_pk: *const libc::c_uchar,
        server_sk: *const libc::c_uchar,
        client_pk: *const libc::c_uchar,
    ) -> libc::c_int;
}
