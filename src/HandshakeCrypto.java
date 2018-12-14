import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto {
    public static byte[] encrypt(byte[] plaintext, Key key) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] ciphertext = cipher.doFinal(plaintext);
        return ciphertext;
    }

    public static byte[] decrypt(byte[] ciphertext, Key key) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plaintext = cipher.doFinal(ciphertext);
        return plaintext;
    }

    public static PublicKey getPublicKeyFromCertFile(String certFile) throws FileNotFoundException, CertificateException {
        InputStream inputStreamCertFile = new FileInputStream(certFile);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate)certificateFactory.generateCertificate(inputStreamCertFile);

        return cert.getPublicKey();
    }

    public static PrivateKey getPrivateKeyFromKeyFile(String keyFile) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        InputStream inputStreamKeyFile = new FileInputStream(keyFile);

        byte[] privateKeyByteArray = inputStreamKeyFile.readAllBytes();

        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyByteArray);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
    }

}
