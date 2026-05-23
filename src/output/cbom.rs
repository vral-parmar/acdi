#![forbid(unsafe_code)]

//! CycloneDX 1.7 CBOM emitter.
//!
//! Spec: https://cyclonedx.org/specification/overview/
//! The cryptographic component schema was enhanced in CycloneDX 1.7 (October 2025).

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::{asset::AssetType, CryptoAsset, Primitive};

// ── CycloneDX 1.7 document types ─────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bom {
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    pub version: u32,
    pub metadata: Metadata,
    pub components: Vec<Component>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub timestamp: String,
    pub tools: Vec<Tool>,
}

#[derive(Serialize, Deserialize)]
pub struct Tool {
    pub vendor: String,
    pub name: String,
    pub version: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Component {
    #[serde(rename = "type")]
    pub component_type: String,
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "cryptoProperties")]
    pub crypto_properties: CryptoProperties,
    pub evidence: ComponentEvidence,
    /// Structured acdi-specific properties for machine-readable diff and tooling
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<Property>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Property {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CryptoProperties {
    #[serde(rename = "assetType")]
    pub asset_type: String,
    #[serde(rename = "algorithmProperties", skip_serializing_if = "Option::is_none")]
    pub algorithm_properties: Option<AlgorithmProperties>,
    #[serde(rename = "oid", skip_serializing_if = "Option::is_none")]
    pub oid: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlgorithmProperties {
    pub primitive: String,
    #[serde(rename = "parameterSetIdentifier", skip_serializing_if = "Option::is_none")]
    pub parameter_set_identifier: Option<String>,
    #[serde(rename = "executionEnvironment")]
    pub execution_environment: String,
    #[serde(rename = "implementationPlatform")]
    pub implementation_platform: String,
    #[serde(rename = "certificationLevel")]
    pub certification_level: Vec<String>,
    pub mode: String,
    pub padding: String,
    #[serde(rename = "cryptoFunctions")]
    pub crypto_functions: Vec<String>,
    #[serde(rename = "nistQuantumSecurityLevel")]
    pub nist_quantum_security_level: u8,
}

#[derive(Serialize, Deserialize)]
pub struct ComponentEvidence {
    pub occurrences: Vec<Occurrence>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Occurrence {
    pub location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(rename = "additionalContext", skip_serializing_if = "Option::is_none")]
    pub additional_context: Option<String>,
}

// ── Conversion ────────────────────────────────────────────────────────────────

pub fn emit_cbom(assets: &[CryptoAsset]) -> String {
    let bom = build_bom(assets);
    serde_json::to_string_pretty(&bom).expect("CBOM serialization is infallible")
}

fn build_bom(assets: &[CryptoAsset]) -> Bom {
    Bom {
        bom_format: "CycloneDX".to_string(),
        spec_version: "1.7".to_string(),
        serial_number: format!("urn:uuid:{}", Uuid::new_v4()),
        version: 1,
        metadata: Metadata {
            timestamp: Utc::now().to_rfc3339(),
            tools: vec![Tool {
                vendor: "acdi".to_string(),
                name: "acdi".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            }],
        },
        components: assets.iter().map(asset_to_component).collect(),
    }
}

fn asset_to_component(asset: &CryptoAsset) -> Component {
    let component_type = match asset.asset_type {
        AssetType::Certificate => "cryptographic-asset",
        AssetType::PrivateKey | AssetType::PublicKey => "cryptographic-asset",
        AssetType::Algorithm => "cryptographic-asset",
        AssetType::Protocol => "cryptographic-asset",
        AssetType::Library => "library",
    };

    let cdx_asset_type = match asset.asset_type {
        AssetType::Certificate => "certificate",
        AssetType::PrivateKey => "private-key",
        AssetType::PublicKey => "public-key",
        AssetType::Algorithm => "algorithm",
        AssetType::Protocol => "protocol",
        AssetType::Library => "library",
    };

    let algorithm_properties = Some(AlgorithmProperties {
        primitive: primitive_to_cdx(&asset.primitive),
        parameter_set_identifier: asset.parameter_set.clone(),
        execution_environment: "unknown".to_string(),
        implementation_platform: "unknown".to_string(),
        certification_level: vec![],
        mode: "unknown".to_string(),
        padding: "unknown".to_string(),
        crypto_functions: vec![crypto_function(&asset.primitive)],
        nist_quantum_security_level: asset.nist_quantum_security,
    });

    let occurrences = asset
        .locations
        .iter()
        .map(|l| Occurrence {
            location: l.source.clone(),
            line: l.line,
            symbol: None,
            additional_context: Some(format!(
                "quantum_safe={} hndl_risk={}",
                asset.quantum_safe, asset.hndl_risk
            )),
        })
        .collect();

    Component {
        component_type: component_type.to_string(),
        bom_ref: Uuid::new_v4().to_string(),
        name: asset.name.clone(),
        description: Some(format!(
            "Quantum safety: {} | HNDL risk: {} | NIST level: {}",
            asset.quantum_safe, asset.hndl_risk, asset.nist_quantum_security
        )),
        crypto_properties: CryptoProperties {
            asset_type: cdx_asset_type.to_string(),
            algorithm_properties,
            oid: asset.oid.clone(),
        },
        evidence: ComponentEvidence { occurrences },
        properties: vec![
            Property {
                name: "acdi:quantum_safe".to_string(),
                value: asset.quantum_safe.to_string(),
            },
            Property {
                name: "acdi:hndl_risk".to_string(),
                value: asset.hndl_risk.to_string(),
            },
            Property {
                name: "acdi:nist_level".to_string(),
                value: asset.nist_quantum_security.to_string(),
            },
        ],
    }
}

fn primitive_to_cdx(p: &Primitive) -> String {
    match p {
        Primitive::PublicKeyEncryption => "pke",
        Primitive::KeyEncapsulationMechanism => "kem",
        Primitive::DigitalSignature => "signature",
        Primitive::KeyDerivation => "kdf",
        Primitive::KeyAgreement => "key-agree",
        Primitive::BlockCipher => "block-cipher",
        Primitive::StreamCipher => "stream-cipher",
        Primitive::Hash => "hash",
        Primitive::Mac => "mac",
        Primitive::PostQuantumKem => "kem",
        Primitive::PostQuantumSignature => "signature",
        Primitive::Other => "other",
    }
    .to_string()
}

fn crypto_function(p: &Primitive) -> String {
    match p {
        Primitive::PublicKeyEncryption => "encrypt",
        Primitive::KeyEncapsulationMechanism | Primitive::PostQuantumKem => "encapsulate",
        Primitive::DigitalSignature | Primitive::PostQuantumSignature => "sign",
        Primitive::KeyDerivation => "derive",
        Primitive::KeyAgreement => "agree",
        Primitive::BlockCipher | Primitive::StreamCipher => "encrypt",
        Primitive::Hash => "digest",
        Primitive::Mac => "authenticate",
        Primitive::Other => "other",
    }
    .to_string()
}

