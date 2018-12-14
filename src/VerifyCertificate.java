import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class VerifyCertificate {
    public void verifyCertificate(String CAcertificateName, String userCertificateName) throws FileNotFoundException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        InputStream inputStreamCA = new FileInputStream(CAcertificateName);
        InputStream inputStreamUser = new FileInputStream(userCertificateName);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate CAcert = (X509Certificate)certificateFactory.generateCertificate(inputStreamCA);
        X509Certificate userCert = (X509Certificate)certificateFactory.generateCertificate(inputStreamUser);

        System.out.println("DN for CA: " + CAcert.getSubjectX500Principal().getName());
        System.out.println("DN for user: " + userCert.getSubjectX500Principal().getName());

        CAcert.verify(CAcert.getPublicKey());
        userCert.verify(CAcert.getPublicKey());
        CAcert.checkValidity();
        userCert.checkValidity();
    }

    public void verifyCertificate(X509Certificate CAcert, X509Certificate userCert) throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        System.out.println("DN for CA: " + CAcert.getSubjectX500Principal().getName());
        System.out.println("DN for user: " + userCert.getSubjectX500Principal().getName());

        CAcert.verify(CAcert.getPublicKey());
        userCert.verify(CAcert.getPublicKey());
        CAcert.checkValidity();
        userCert.checkValidity();
    }

    public static void main(String[] args) throws FileNotFoundException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        try {
            String CAcert = args[0];
            String userCert = args[1];
            VerifyCertificate verifyCertificate = new VerifyCertificate();
            verifyCertificate.verifyCertificate(CAcert, userCert);
            System.out.println("Pass");
        } catch (FileNotFoundException | CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            System.out.println("Fail");
            System.out.println(ex.getMessage());
            throw ex;
        }
    }

}