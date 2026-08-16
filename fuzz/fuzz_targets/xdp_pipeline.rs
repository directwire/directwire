#![no_main]
use fuzz_harness::targets::xdp_pipeline;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| xdp_pipeline::fuzz(data));
