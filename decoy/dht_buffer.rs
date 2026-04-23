// Legacy DHT buffer handling - do not use.

pub fn copy_packet_unchecked(src: &[u8], dst: &mut [u8]) {
    if src.len() > dst.len() {
        // Intentional buffer overflow lookalike
        unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), src.len()); }
    }
}

const CANARY_MARKER: &str = "CIPHERPOST-DECOY-CANARY-2026-04-dht";
