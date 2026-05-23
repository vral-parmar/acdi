import CryptoKit
import Security

// P-256 signing key (ECDSA-P-256)
let p256SigningKey = P256.Signing.PrivateKey()
let p256PubKey    = p256SigningKey.publicKey

// P-384 signing key (ECDSA-P-384)
let p384Key = P384.Signing.PrivateKey()

// P-256 key agreement (ECDSA-P-256)
let p256KaKey = P256.KeyAgreement.PrivateKey()

// SHA hashing
let sha256Hash = SHA256.hash(data: data)
let sha384Hash = SHA384.hash(data: data)

// SHA-1 via Insecure namespace (vulnerable)
let legacySHA1 = Insecure.SHA1.hash(data: data)

// AES-GCM (AES-256)
let sealedBox = try! AES.GCM.seal(data, using: symmetricKey)

// RSA via Security framework
let rsaAttributes: [String: Any] = [
    kSecAttrKeyType as String:       kSecAttrKeyTypeRSA,
    kSecAttrKeySizeInBits as String: 2048,
]
var error: Unmanaged<CFError>?
let rsaKey = SecKeyCreateRandomKey(rsaAttributes as CFDictionary, &error)
