#![no_main]
use fuzz_harness::targets::homa_transport;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| homa_transport::fuzz(data));
