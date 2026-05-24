#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = acdi::detect::detect_in_bytes_pem_der(data, "fuzz", "");
    let _ = acdi::detect::detect_in_bytes_pem_der(data, "fuzz", "certificate");
    let _ = acdi::detect::detect_in_bytes_pem_der(data, "fuzz", "key");
});
