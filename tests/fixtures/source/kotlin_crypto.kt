import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.MessageDigest
import javax.crypto.KeyGenerator
import javax.crypto.SecretKeySpec

// Standard JCA (shared with Java rules)
val jcaRsa = KeyPairGenerator.getInstance("RSA")
val jcaEc  = KeyPairGenerator.getInstance("EC")

// Android Keystore — RSA key pair
val rsaKpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")

// Android Keystore — EC key pair
val ecKpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")

// Android Keystore — AES secret key
val aesKg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")

// KeyProperties digest constants
val sha256 = KeyProperties.DIGEST_SHA256
val sha1   = KeyProperties.DIGEST_SHA1
val md5    = KeyProperties.DIGEST_MD5

// HMAC key spec
val hmacKey256 = SecretKeySpec(rawKey, "HmacSHA256")
val hmacKey1   = SecretKeySpec(rawKey, "HmacSHA1")
