//! `SHA-256`.
//!
//! There has been considerable degradation of public confidence in the
//! security conjectures for many hash functions, including `SHA-256`.
//! However, for the moment, there do not appear to be alternatives that
//! inspire satisfactory levels of confidence. One can hope that NIST's
//! SHA-3 competition will improve the situation.
use ffi::{
    crypto_hash_sha256, crypto_hash_sha256_BYTES, crypto_hash_sha256_final,
    crypto_hash_sha256_init, crypto_hash_sha256_state, crypto_hash_sha256_update,
};

hash_module!(
    crypto_hash_sha256,
    crypto_hash_sha256_BYTES,
    64,
    crypto_hash_sha256_state,
    crypto_hash_sha256_init,
    crypto_hash_sha256_update,
    crypto_hash_sha256_final
);

#[cfg(test)]
mod test {
    use super::*;

    fn streaming_hash(msg: &[u8]) -> Digest {
        let mut s = State::init();
        s.update(msg);
        s.finalize()
    }

    fn streaming_hash_chunks(chunks: Vec<&[u8]>) -> Digest {
        let mut s = State::init();
        for msg in chunks {
            s.update(msg);
        }
        s.finalize()
    }

    #[test]
    fn test_vector_1() {
        // hash of empty string
        let x = [];
        let h_expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        let Digest(h) = hash(&x);
        let Digest(h1) = streaming_hash(&x);
        let Digest(h2) = streaming_hash_chunks(vec![&[], &[]]);
        assert_eq!(h, h_expected);
        assert_eq!(h1, h_expected);
        assert_eq!(h2, h_expected);
    }

    #[test]
    fn test_vector_2() {
        // The quick brown fox jumps over the lazy dog
        let x = [
            0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77,
            0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76,
            0x65, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f,
            0x67,
        ];
        let h_expected = [
            0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08,
            0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf,
            0x37, 0xc9, 0xe5, 0x92,
        ];
        let Digest(h) = hash(&x);
        let Digest(h1) = streaming_hash(&x);
        let chunks = x.split_at(x.len() / 2);
        let Digest(h2) = streaming_hash_chunks(vec![chunks.0, chunks.1]);
        assert_eq!(h, h_expected);
        assert_eq!(h1, h_expected);
        assert_eq!(h2, h_expected);
    }

    fn test_nist_vector(filename: &str) {
        use std::{
            fs::File,
            io::{BufRead, BufReader},
        };

        let mut r = BufReader::new(File::open(filename).unwrap());
        let mut line = String::new();

        while let Ok(len) = r.read_line(&mut line) {
            if len == 0 {
                break;
            }
            if line.starts_with("Len = ") {
                let len: usize = line[6..].trim().parse().unwrap();
                line.clear();
                r.read_line(&mut line).unwrap();
                let rawmsg = hex::decode(line[6..].trim_end()).unwrap();
                let msg = &rawmsg[..len / 8];
                line.clear();
                r.read_line(&mut line).unwrap();
                let md = hex::decode(line[5..].trim_end()).unwrap();
                let Digest(digest) = hash(msg);
                let Digest(digest1) = streaming_hash(msg);
                assert_eq!(&digest[..], &md[..]);
                assert_eq!(&digest1[..], &md[..]);
                line.clear();
            }
        }
    }

    fn test_hash_for_file(file: &str) -> Digest {
        use std::fs::File;
        use std::io::{BufReader, Read};

        let mut r = BufReader::new(File::open(file).unwrap());
        let mut s = State::init();
        let mut buf = [0; 512];
        while let Ok(len) = r.read(&mut buf) {
            if len == 0 {
                break;
            }
            s.update(&buf[..len]);
        }
        s.finalize()
    }

    #[test]
    fn test_vectors_nist_short() {
        test_nist_vector("testvectors/SHA256ShortMsg.rsp");
    }

    #[test]
    fn test_vectors_nist_long() {
        test_nist_vector("testvectors/SHA256LongMsg.rsp");
    }

    #[test]
    fn test_streaming_hashing() {
        let Digest(hash_short) = test_hash_for_file("testvectors/SHA256ShortMsg.rsp");
        let Digest(hash_long) = test_hash_for_file("testvectors/SHA256LongMsg.rsp");

        let (real_short, real_long) = if cfg!(unix) {
            (
                hex::decode("49f6d54d0750bbff511e915b1045c9dd7363c3005f8498c3804956805d72c5f8")
                    .unwrap(),
                hex::decode("12e92098fbd93fb6ebad3ff15e9592a3800d90a69cd5382f7b055132282b143b")
                    .unwrap(),
            )
        } else {
            (
                hex::decode("2fe1398dfaa6635656d5b4e3956eb87258f6ab2c19050b8b8f2fd5f715160025")
                    .unwrap(),
                hex::decode("23297bf12788e13732763abcf39874f24332024ee31038e0858dbe9224722314")
                    .unwrap(),
            )
        };

        assert_eq!(&hash_short[..], &real_short[..]);
        assert_eq!(&hash_long[..], &real_long[..]);
    }
}
