import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class Handshake {
    /* Static data -- replace with handshake! */

    /* Where the client forwarder forwards data from  */
    //public static final String serverHost = "localhost";
    //public static final int serverPort = 4412;

    /* The final destination */
    //public static String targetHost = "localhost";
    //public static int targetPort = 6789;

    private String targetHost;
    private int targetPort;

    private String serverHost;
    private int serverPort;

    private HandshakeMessage clientHello;
    private HandshakeMessage serverHello;
    private HandshakeMessage forwardMessage;
    private HandshakeMessage sessionMessage;

    private X509Certificate clientCert;
    private X509Certificate serverCert;

    private SessionKey sessionKey;
    private IvParameterSpec IV;

    private SessionEncrypter sessionEncrypter;
    private SessionDecrypter sessionDecrypter;

    public void setAndSendClientHello(String clientCertName, Socket socket) throws IOException, CertificateException {
        clientHello = new HandshakeMessage();
        System.out.println("ClientHello");
        InputStream inputStream = new FileInputStream(clientCertName);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        clientCert = (X509Certificate)certificateFactory.generateCertificate(inputStream);

        String clientCertBase64EncodedString = Base64.getEncoder().encodeToString(clientCert.getEncoded());
        clientHello.putParameter("MessageType", "ClientHello");
        clientHello.putParameter("Certificate", clientCertBase64EncodedString);
        clientHello.send(socket);
    }

    public void setAndSendServerHello(String serverCertName, String CACertName, Socket socket) throws IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        serverHello = new HandshakeMessage();
        System.out.println("ServerHello");
        HandshakeMessage fromClient = new HandshakeMessage();
        fromClient.recv(socket);
        if (fromClient.getParameter("MessageType").equals("ClientHello")) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            String clientCertAsString = fromClient.getParameter("Certificate");
            byte[] clientCertAsBytes = Base64.getDecoder().decode(clientCertAsString);
            InputStream clientCertInputStream = new ByteArrayInputStream(clientCertAsBytes);
            clientCert = (X509Certificate)certificateFactory.generateCertificate(clientCertInputStream);

            InputStream CAcertInputStream = new FileInputStream(CACertName);
            X509Certificate CAcert = (X509Certificate)certificateFactory.generateCertificate(CAcertInputStream);

            VerifyCertificate certificateVerifyer = new VerifyCertificate();
            certificateVerifyer.verifyCertificate(CAcert, clientCert);

            InputStream serverCertInputStream = new FileInputStream(serverCertName);
            serverCert = (X509Certificate)certificateFactory.generateCertificate(serverCertInputStream);

            String serverCertBase64EncodedString = Base64.getEncoder().encodeToString(serverCert.getEncoded());
            serverHello.putParameter("MessageType", "ServerHello");
            serverHello.putParameter("Certificate", serverCertBase64EncodedString);
            serverHello.send(socket);
        } else {
            System.out.println("Wrong type of parameter, expected ClientHello.");
            socket.close();
        }
    }

    public void setAndSendForwardMessage(String targetHost, String targetPort, String CACertName, Socket socket) throws IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        forwardMessage = new HandshakeMessage();
        System.out.println("Forward");
        HandshakeMessage fromServer = new HandshakeMessage();
        fromServer.recv(socket);
        if (fromServer.getParameter("MessageType").equals("ServerHello")) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            String serverCertAsString = fromServer.getParameter("Certificate");
            byte[] serverCertAsBytes = Base64.getDecoder().decode(serverCertAsString);
            InputStream serverCertInputStream = new ByteArrayInputStream(serverCertAsBytes);
            serverCert = (X509Certificate)certificateFactory.generateCertificate(serverCertInputStream);

            InputStream CAcertInputStream = new FileInputStream(CACertName);
            X509Certificate CAcert = (X509Certificate)certificateFactory.generateCertificate(CAcertInputStream);

            VerifyCertificate certificateVerifyer = new VerifyCertificate();
            certificateVerifyer.verifyCertificate(CAcert, serverCert);

            forwardMessage.putParameter("MessageType", "Forward");
            forwardMessage.putParameter("TargetHost", targetHost);
            forwardMessage.putParameter("TargetPort", targetPort);
            forwardMessage.send(socket);
        } else {
            System.out.println("Wrong type of parameter, expected ServerHello.");
            socket.close();
        }
    }

    public void setAndSendSessionMessage(String serverHost, String serverPort, int keyLength, Socket socket) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        sessionMessage = new HandshakeMessage();
        System.out.println("SessionMessage");
        HandshakeMessage fromClient = new HandshakeMessage();
        fromClient.recv(socket);
        if (fromClient.getParameter("MessageType").equals("Forward")) {
            targetHost = fromClient.getParameter("TargetHost");
            targetPort = Integer.parseInt(fromClient.getParameter("TargetPort"));

            sessionKey = new SessionKey(keyLength);
            SecureRandom randomByteGenerator = new SecureRandom();
            IV = new IvParameterSpec(randomByteGenerator.generateSeed(16));
            sessionDecrypter = new SessionDecrypter(sessionKey, IV);

            PublicKey clientsPublicKey = clientCert.getPublicKey();
            Cipher cipherKey = Cipher.getInstance("RSA");
            Cipher cipherIV = Cipher.getInstance("RSA");
            cipherKey.init(Cipher.ENCRYPT_MODE, clientsPublicKey);
            cipherIV.init(Cipher.ENCRYPT_MODE, clientsPublicKey);
            byte[] encryptedSessionKeyAsBytes = cipherKey.doFinal(sessionKey.encodeKey().getBytes());
            byte[] encryptedIVAsBytes = cipherIV.doFinal(IV.getIV());

            sessionMessage.putParameter("MessageType", "Session");
            sessionMessage.putParameter("SessionKey", Base64.getEncoder().encodeToString(encryptedSessionKeyAsBytes));
            sessionMessage.putParameter("SessionIV", Base64.getEncoder().encodeToString(encryptedIVAsBytes));
            sessionMessage.putParameter("ServerHost", serverHost);
            sessionMessage.putParameter("ServerPort", serverPort);
            sessionMessage.send(socket);
        } else {
            System.out.println("Wrong type of parameter, expected Forward.");
            socket.close();
        }
    }

    public void finishHandshake(Socket socket, String clientPrivateKeyName) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        HandshakeMessage fromServer = new HandshakeMessage();
        System.out.println("Client finishing handshake.");
        fromServer.recv(socket);
        if (fromServer.getParameter("MessageType").equals("Session")) {
            serverHost = fromServer.getParameter("ServerHost");
            serverPort = Integer.parseInt(fromServer.getParameter("ServerPort"));

            PrivateKey clientsPrivateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(clientPrivateKeyName);
            Cipher cipherKey = Cipher.getInstance("RSA");
            Cipher cipherIV = Cipher.getInstance("RSA");
            cipherKey.init(Cipher.DECRYPT_MODE, clientsPrivateKey);
            cipherIV.init(Cipher.DECRYPT_MODE, clientsPrivateKey);
            byte[] decryptedSessionKeyAsBytes = cipherKey.doFinal(Base64.getDecoder().decode(fromServer.getParameter("SessionKey")));
            byte[] decryptedIVAsBytes = cipherIV.doFinal(Base64.getDecoder().decode(fromServer.getParameter("SessionIV")));
            String decryptedSessionKeyAsString = new String(decryptedSessionKeyAsBytes);

            sessionKey = new SessionKey(decryptedSessionKeyAsString);
            IV = new IvParameterSpec(decryptedIVAsBytes);

            sessionEncrypter = new SessionEncrypter(sessionKey, IV);

            System.out.println("Handshake complete!");
        } else {
            System.out.println("Wrong type of parameter, expected Session.");
            socket.close();
        }
    }

    public String getTargetHost() {
        return targetHost;
    }

    public int getTargetPort() {
        return targetPort;
    }

    public String getServerHost() {
        return serverHost;
    }

    public int getServerPort() {
        return serverPort;
    }

    public SessionEncrypter getSessionEncrypter() { return sessionEncrypter; }

    public SessionDecrypter getSessionDecrypter() { return sessionDecrypter; }

}
