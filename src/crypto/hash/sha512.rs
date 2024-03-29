//! `SHA-512`.
//!
//! There has been considerable degradation of public confidence in the
//! security conjectures for many hash functions, including `SHA-512`.
//! However, for the moment, there do not appear to be alternatives that
//! inspire satisfactory levels of confidence. One can hope that NIST's
//! SHA-3 competition will improve the situation.
use ffi::{
    crypto_hash_sha512, crypto_hash_sha512_BYTES, crypto_hash_sha512_final,
    crypto_hash_sha512_init, crypto_hash_sha512_state, crypto_hash_sha512_update,
};

hash_module!(
    crypto_hash_sha512,
    crypto_hash_sha512_BYTES,
    128,
    crypto_hash_sha512_state,
    crypto_hash_sha512_init,
    crypto_hash_sha512_update,
    crypto_hash_sha512_final
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
        // corresponding to tests/hash.c, tests/hash2.cpp,
        // tests/hash3.c and tests/hash4.cpp from NaCl
        let x = [0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67, 0xa];
        let h_expected = [
            0x24, 0xf9, 0x50, 0xaa, 0xc7, 0xb9, 0xea, 0x9b, 0x3c, 0xb7, 0x28, 0x22, 0x8a, 0x0c,
            0x82, 0xb6, 0x7c, 0x39, 0xe9, 0x6b, 0x4b, 0x34, 0x47, 0x98, 0x87, 0x0d, 0x5d, 0xae,
            0xe9, 0x3e, 0x3a, 0xe5, 0x93, 0x1b, 0xaa, 0xe8, 0xc7, 0xca, 0xcf, 0xea, 0x4b, 0x62,
            0x94, 0x52, 0xc3, 0x80, 0x26, 0xa8, 0x1d, 0x13, 0x8b, 0xc7, 0xaa, 0xd1, 0xaf, 0x3e,
            0xf7, 0xbf, 0xd5, 0xec, 0x64, 0x6d, 0x6c, 0x28,
        ];
        let Digest(h) = hash(&x);
        let Digest(h1) = streaming_hash(&x);
        let chunks = x.split_at(x.len() / 2);
        let Digest(h2) = streaming_hash_chunks(vec![chunks.0, chunks.1]);
        assert_eq!(&h[..], &h_expected[..]);
        assert_eq!(&h1[..], &h_expected[..]);
        assert_eq!(&h2[..], &h_expected[..]);
    }

    fn test_nist_vector(filename: &str) {
        use std::fs::File;
        use std::io::{BufRead, BufReader};

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
        loop {
            let mut buf = [0; 512];
            let len = r.read(&mut buf).unwrap();
            if len == 0 {
                break;
            }
            s.update(&buf[..len]);
        }
        s.finalize()
    }

    #[test]
    fn test_vectors_nist_short() {
        test_nist_vector("testvectors/SHA512ShortMsg.rsp");
    }

    #[test]
    fn test_vectors_nist_long() {
        test_nist_vector("testvectors/SHA512LongMsg.rsp");
    }

    #[test]
    fn test_streaming_hashing() {
        let Digest(hash_short) = test_hash_for_file("testvectors/SHA512ShortMsg.rsp");
        let Digest(hash_long) = test_hash_for_file("testvectors/SHA512LongMsg.rsp");

        let (real_short, real_long) = if cfg!(unix) {
            (
                hex::decode(
                    "c0fa02fa36680458c0143a1b837eb87eefc7bbec299f1b1ec2bc304ebf516ba\
                    cc5020bc04a94fe00fb3dcec64b938bf347ed45431dec3dc2a2e8bb4d89e785cf",
                )
                .unwrap(),
                hex::decode(
                    "1e77643d79d0836b97fae313393f01cdc639ab20c97dc56f60a303e25a73d8a\
                    fd4ad4e08fb1d45b0b2ce20ce64d63a82e1f750ba797435120c02f94d0404c015",
                )
                .unwrap(),
            )
        } else {
            (
                hex::decode(
                    "ef27a9fcbeb037d00bed853f496588d456d8caee85669f3a4e77dd9fd406da0\
                    742a04fdcaeca0cc64d5f77877b51f363e0007038928c4654b4410aeb71d246cf",
                )
                .unwrap(),
                hex::decode(
                    "2f91df6c65031255d529593a04b9166bb6842bb574eb18bad3d3be24fc7d1e9\
                    f6ffe0433ce029f91d81c91a3f741422373101408d723602ed7aa0862ac017323",
                )
                .unwrap(),
            )
        };

        assert_eq!(&hash_short[..], &real_short[..]);
        assert_eq!(&hash_long[..], &real_long[..]);
    }
}
