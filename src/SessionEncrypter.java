import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class SessionEncrypter {
    private SessionKey sessionKey;
    private IvParameterSpec IV;

    public SessionEncrypter(Integer keyLength) throws NoSuchAlgorithmException {
        this.sessionKey = new SessionKey(keyLength);
        SecureRandom randomByteGenerator = new SecureRandom();
        this.IV = new IvParameterSpec(randomByteGenerator.generateSeed(16));
    }

    public CipherOutputStream openCipherOutputStream(OutputStream output) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, this.sessionKey.getSecretKey(), this.IV);
        return new CipherOutputStream(output, cipher);
    }

    public String encodeKey() {
        return this.sessionKey.encodeKey();
    }

    public String encodeIV() {
        return Base64.getEncoder().encodeToString(this.IV.getIV());
    }
}
