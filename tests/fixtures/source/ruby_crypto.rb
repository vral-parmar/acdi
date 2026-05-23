require 'openssl'
require 'jwt'

# RSA key generation — RSA-2048
rsa_key = OpenSSL::PKey::RSA.new(2048)
rsa_pub  = rsa_key.public_key

# EC key generation — ECDSA-P-256
ec_key = OpenSSL::PKey::EC.new("prime256v1")
ec_key.generate_key

# Digest — SHA-1 (vulnerable), SHA-256 (adequate)
sha1_digest   = OpenSSL::Digest::SHA1.new
sha256_digest = OpenSSL::Digest::SHA256.new
md5_digest    = OpenSSL::Digest::MD5.new

# AES cipher — AES-128
cipher = OpenSSL::Cipher::AES.new("128-CBC")
cipher.encrypt

# JWT signing with RS256 → RSA-2048
payload = { sub: 'user_id', exp: Time.now.to_i + 3600 }
token = JWT.encode(payload, rsa_key, 'RS256')
decoded = JWT.decode(token, rsa_pub, true, algorithms: ['RS256'])
