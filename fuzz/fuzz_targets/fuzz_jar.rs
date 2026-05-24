#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let dir = tempfile::tempdir().unwrap();
    // Fuzz as class file
    let class = dir.path().join("Fuzz.class");
    std::fs::write(&class, data).unwrap();
    let _ = acdi::detect::detect_in_file(&class);
    // Fuzz as JAR
    let jar = dir.path().join("fuzz.jar");
    std::fs::write(&jar, data).unwrap();
    let _ = acdi::detect::detect_in_file(&jar);
});
