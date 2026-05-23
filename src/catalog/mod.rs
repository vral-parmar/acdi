#![forbid(unsafe_code)]

pub mod algorithms;
pub mod oids;

pub use algorithms::{AlgorithmInfo, ALGORITHM_CATALOG};
pub use oids::oid_to_algorithm;
