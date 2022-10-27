package encrypt.decrypt.test;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

public class EncryptedFileTest {

    EncryptDecryptDataTest rsa;

    @BeforeEach
    public void setUp() throws Exception {
        rsa = new EncryptDecryptDataTest(
                "./private_key_rsa_4096_pkcs8-exported.pem"
                , "./public_key_rsa_4096_pkcs8-exported.pem"
        );
    }

    @Test
    public void testEncryptedFile()
            throws Exception {
        // Setup
        String expected = getFileAsString("./file_unencrypted.txt");

        String encryptedAndEncoded = getFileAsString("./file_encrypted_and_encoded.txt");


        // Test
        String actual = rsa.decryptFromBase64(encryptedAndEncoded);
        System.out.printf("%s%n", actual);

        // Assert
        Assertions.assertEquals(expected, actual);
    }

    private String getFileAsString(String classPathResourceLocation) throws Exception {
        InputStream is = this.getClass()
                .getClassLoader()
                .getResourceAsStream(classPathResourceLocation);

        byte[] bytes = is.readAllBytes();
        is.close();
        return new String(bytes);
    }
}
