import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SessionDecrypter {
    private String key;
    private String IV;

    public SessionDecrypter(String key, String IV) {
        this.key = key;
        this.IV = IV;
    }

    public CipherInputStream openCipherInputStream(InputStream input) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        SessionKey sessionKey = new SessionKey(this.key);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(Base64.getDecoder().decode(this.IV));
        cipher.init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey(), ivParameterSpec);
        return new CipherInputStream(input, cipher);
    }
}
