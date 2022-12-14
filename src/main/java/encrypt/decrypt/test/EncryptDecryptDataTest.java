package encrypt.decrypt.test;

import javax.crypto.Cipher;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EncryptDecryptDataTest {

    private KeyFactory keyFactory;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public EncryptDecryptDataTest(
            String privateKeyClassPathResource
            , String publicKeyClassPathResource
    ) throws Exception {
        setKeyFactory();
        setPrivateKey(privateKeyClassPathResource);
        setPublicKey(publicKeyClassPathResource);
    }

    protected void setKeyFactory() throws Exception {
        this.keyFactory = KeyFactory.getInstance("RSA");
    }

    protected void setPrivateKey(String classpathResource)
            throws Exception {
        InputStream is = this.getClass().getClassLoader()
                .getResourceAsStream(classpathResource);

        String stringBefore = new String(is.readAllBytes());
        is.close();

        String stringAfter = stringBefore
                .replaceAll("\\n", "")
                .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("-----END PRIVATE KEY-----", "")
                .trim();

        byte[] decoded = Base64
                .getDecoder()
                .decode(stringAfter);

        KeySpec keySpec = new PKCS8EncodedKeySpec(decoded);

        privateKey = keyFactory.generatePrivate(keySpec);
    }

    protected void setPublicKey(String classpathResource)
            throws Exception {

        InputStream is = this.getClass().getClassLoader()
                .getResourceAsStream(classpathResource);

        String stringBefore = new String(is.readAllBytes());
        is.close();

        String stringAfter = stringBefore
                .replaceAll("\\n", "")
                .replaceAll("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("-----END PUBLIC KEY-----", "")
                .trim()
                ;

        byte[] decoded = Base64.getDecoder().decode(stringAfter);

        KeySpec keySpec = new X509EncodedKeySpec(decoded);

        publicKey = keyFactory.generatePublic(keySpec);
    }

    public String encryptToBase64(String plainText) {
        String encoded = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encrypted = cipher.doFinal(plainText.getBytes());
            encoded = Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encoded;
    }

    public String decryptFromBase64(String base64EncodedEncryptedBytes) {
        String plainText = null;
        try {
            final Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decoded = Base64
                    .getDecoder()
                    .decode(base64EncodedEncryptedBytes);
            byte[] decrypted = cipher.doFinal(decoded);
            plainText = new String(decrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return plainText;
    }
}
