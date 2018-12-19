import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class SessionDecrypter {
    private SessionKey key;
    private IvParameterSpec IV;

    /*public SessionDecrypter(String key, String IV) {
        this.key = key;
        this.IV = IV;
    }*/

    public SessionDecrypter(SessionKey key, IvParameterSpec IV) {
        this.key = key;
        this.IV = IV;
    }

    public CipherInputStream openCipherInputStream(InputStream input) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key.getSecretKey(), IV);
        return new CipherInputStream(input, cipher);
    }
}
