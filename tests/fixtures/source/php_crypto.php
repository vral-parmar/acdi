<?php

// RSA key generation
$config = [
    'private_key_bits' => 2048,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
];
$key_pair = openssl_pkey_new($config);

// AES encryption — AES-128
$encrypted_128 = openssl_encrypt($plaintext, 'aes-128-cbc', $key, 0, $iv);

// AES encryption — AES-256
$encrypted_256 = openssl_encrypt($plaintext, 'aes-256-gcm', $key, 0, $iv, $tag);

// 3DES (legacy)
$encrypted_3des = openssl_encrypt($plaintext, 'des-ede3-cbc', $key, 0, $iv);

// Hash functions
$sha1_hash   = hash('sha1', $data);
$sha256_hash = hash('sha256', $data);
$md5_hash    = md5($data);
$sha1_direct = sha1($data);

// RSA signing
openssl_sign($data, $signature, $key_pair, OPENSSL_ALGO_SHA256);
