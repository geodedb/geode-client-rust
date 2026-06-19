//! Fuzz target: crypto decrypt must never panic on arbitrary input, and
//! encrypt->decrypt must round-trip.
#![no_main]

use geode_client::Cipher;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let cipher = Cipher::new(&[b'k'; 32]).unwrap();
    // decrypt must not panic on arbitrary bytes
    let _ = cipher.decrypt(data);
    // round-trip
    if let Ok(ct) = cipher.encrypt(data) {
        let pt = cipher.decrypt(&ct).expect("roundtrip decrypt");
        assert_eq!(pt, data);
    }
});
