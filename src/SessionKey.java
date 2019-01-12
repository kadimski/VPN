import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;


public class SessionKey {
    private SecretKey secKey;

    public SessionKey(Integer keyLength) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecureRandom secRand = new SecureRandom();
        keyGen.init(keyLength, secRand);
        this.secKey = keyGen.generateKey();
    }

    public SessionKey(String encodedKey){
        byte[] decodedKeyByte = Base64.getDecoder().decode(encodedKey);
        this.secKey = new SecretKeySpec(decodedKeyByte, "AES");
    }

    public SessionKey (byte[] key){
        this.secKey = new SecretKeySpec(key, "AES");
    }

    public SecretKey getSecretKey(){
        return this.secKey;
    }

    public String encodeKey(){
        return Base64.getEncoder().encodeToString(secKey.getEncoded());
    }
}
