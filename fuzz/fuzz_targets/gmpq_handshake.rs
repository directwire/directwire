#![no_main]
use fuzz_harness::targets::gmpq_handshake;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| gmpq_handshake::fuzz(data));
