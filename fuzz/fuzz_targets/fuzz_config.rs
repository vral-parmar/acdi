#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let dir = tempfile::tempdir().unwrap();
        // Fuzz as YAML
        let yaml = dir.path().join("fuzz.yaml");
        std::fs::write(&yaml, text).unwrap();
        let _ = acdi::detect::detect_in_file(&yaml);
        // Fuzz as Terraform HCL
        let tf = dir.path().join("fuzz.tf");
        std::fs::write(&tf, text).unwrap();
        let _ = acdi::detect::detect_in_file(&tf);
    }
});
