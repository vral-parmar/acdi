using System.Security.Cryptography;

// RSA — various ways
using var rsa2048      = RSA.Create(2048);
using var rsaCsp2048   = new RSACryptoServiceProvider(2048);
using var rsaCng4096   = new RSACng(4096);

// ECDSA
using var ecdsaP256    = ECDsa.Create(ECCurve.NamedCurves.nistP256);
using var ecdsaP384    = ECDsa.Create(ECCurve.NamedCurves.nistP384);
using var ecdsaCng256  = new ECDsaCng(256);

// AES
using var aes          = Aes.Create();
using var aesManaged   = new AesManaged();
using var aesCsp       = new AesCryptoServiceProvider();

// 3DES
using var tripleDes    = TripleDES.Create();
using var tripleDesCsp = new TripleDESCryptoServiceProvider();

// Hash algorithms
using var md5          = MD5.Create();
using var sha1         = SHA1.Create();
using var sha256       = SHA256.Create();
using var sha384       = SHA384.Create();
using var sha512       = SHA512.Create();

// HMAC
using var hmac256      = new HMACSHA256();
using var hmac1        = new HMACSHA1();
using var hmacMd5      = new HMACMD5();
