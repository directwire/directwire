//! OS random adapter.
//!
//! libsmx key-generation interfaces require `rand_core 0.6`'s `RngCore`;
//! this module provides a minimal adapter over getrandom (the OS CSPRNG) to
//! avoid pulling in the full `rand` family (dependency minimization).

/// Randomness source backed by the OS CSPRNG
#[derive(Clone, Copy, Debug, Default)]
pub struct SysRng;

impl SysRng {
    pub fn new() -> Self {
        SysRng
    }
}

impl rand_core_06::RngCore for SysRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // The only sane way to handle getrandom failure is to abort immediately
        // (cryptographic code must not fall back to weak randomness).
        getrandom::fill(dest).expect("OS CSPRNG unavailable; cannot continue safely");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core_06::Error> {
        getrandom::fill(dest).map_err(|e| {
            let code = std::num::NonZeroU32::new(e.raw_os_error().unwrap_or(0).unsigned_abs())
                .unwrap_or(std::num::NonZeroU32::MIN);
            rand_core_06::Error::from(code)
        })
    }
}

impl rand_core_06::CryptoRng for SysRng {}
