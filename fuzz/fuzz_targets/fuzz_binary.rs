#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fuzz_input");
    std::fs::write(&path, data).unwrap();
    let _ = acdi::detect::detect_in_file(&path);
});
