#![forbid(unsafe_code)]

pub mod binary;
pub mod certs;
pub mod config;
pub mod manifest;
pub mod source;

pub use certs::detect_in_bytes_pem_der;

// ── Extension sets ────────────────────────────────────────────────────────────

const SOURCE_EXTENSIONS: &[&str] = &[
    "c", "cpp", "cc", "cxx", "h", "hpp", "hxx", // C/C++
    "py", "pyw",                                  // Python
    "java", "kt", "kts",                          // Java / Kotlin
    "go",                                         // Go
    "rs",                                         // Rust
    "js", "mjs", "ts", "jsx", "tsx",              // JavaScript / TypeScript
    "rb",                                         // Ruby
    "php",                                        // PHP
    "swift",                                      // Swift
    "cs",                                         // C# / .NET
];

const BINARY_EXTENSIONS: &[&str] = &[
    "so", "dylib", "dll", "exe",  // shared libs + executables
    "o", "a", "lib",              // object files
    "wasm",                       // WebAssembly
    "elf",                        // explicit ELF
];

const CONFIG_EXTENSIONS: &[&str] = &[
    "yaml", "yml",        // YAML / Kubernetes manifests
    "toml",               // TOML
    "json",               // JSON (also scanned for JWT alg fields)
    "ini", "cfg", "conf", // INI-style
    "properties",         // Java .properties
    "env",                // dotenv / .env files
    "tf",                 // Terraform HCL
];

/// Detect all crypto assets in a single file, dispatching to the appropriate scanner.
/// Returns an empty vec (not an error) for unrecognised or oversized files.
/// Known package manifest filenames — checked before extension-based dispatch.
const MANIFEST_FILENAMES: &[&str] = &[
    "Cargo.toml",
    "package.json",
    "requirements.txt",
    "Pipfile",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
];

pub fn detect_in_file(path: &std::path::Path) -> anyhow::Result<Vec<crate::model::CryptoAsset>> {
    // Package manifests — matched by filename, takes precedence over extension routing
    // (e.g., Cargo.toml has .toml extension but needs manifest parsing, not config parsing)
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if MANIFEST_FILENAMES.contains(&name) {
            return manifest::scan_manifest(path);
        }
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    // Cert / key files — handled first by extension
    if matches!(
        ext.as_str(),
        "pem" | "crt" | "cer" | "key" | "pub" | "p7b" | "p7c" | "der"
    ) {
        return certs::detect_in_file(path);
    }

    // Source code files
    if SOURCE_EXTENSIONS.contains(&ext.as_str()) {
        return source::scan_source(path);
    }

    // Binary files (by extension)
    if BINARY_EXTENSIONS.contains(&ext.as_str()) {
        return binary::scan_binary(path);
    }

    // Configuration files
    if CONFIG_EXTENSIONS.contains(&ext.as_str()) {
        return config::scan_config(path);
    }

    // Extension-less or unknown — sniff magic bytes
    match (certs::looks_like_pem_pub(path), binary::has_binary_magic(path)) {
        (Ok(true), _) => certs::detect_in_file(path),
        (_, Ok(true)) => binary::scan_binary(path),
        _ => Ok(vec![]),
    }
}
