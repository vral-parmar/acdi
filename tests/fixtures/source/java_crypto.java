// java_crypto.java — fixture for acdi source scanner tests
import java.security.*;
import javax.crypto.*;

public class java_crypto {

    public static KeyPair generateRsaKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public static byte[] hashData(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(data);
    }

    public static Cipher getAesCipher() throws Exception {
        return Cipher.getInstance("AES/CBC/PKCS5Padding");
    }
}
