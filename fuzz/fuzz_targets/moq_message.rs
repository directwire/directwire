#![no_main]
use fuzz_harness::targets::moq_message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| moq_message::fuzz(data));
