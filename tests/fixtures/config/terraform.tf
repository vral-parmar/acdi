# tls_private_key — RSA
resource "tls_private_key" "rsa_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

# tls_private_key — ECDSA P-256
resource "tls_private_key" "ec_key" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

# AWS KMS asymmetric key — RSA_2048
resource "aws_kms_key" "rsa_asymmetric" {
  description              = "RSA asymmetric key"
  customer_master_key_spec = "RSA_2048"
}

# AWS KMS asymmetric key — ECC_NIST_P256
resource "aws_kms_key" "ec_asymmetric" {
  description              = "EC asymmetric key"
  customer_master_key_spec = "ECC_NIST_P256"
}

# AWS KMS symmetric key — AES-256
resource "aws_kms_key" "symmetric" {
  description              = "Symmetric key"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
}

# GCP KMS — EC signing key
resource "google_kms_crypto_key" "ec_sign" {
  version_template {
    algorithm = "EC_SIGN_P256_SHA256"
  }
}
