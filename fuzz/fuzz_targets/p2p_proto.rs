#![no_main]
use fuzz_harness::targets::p2p_proto;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| p2p_proto::fuzz(data));
