package encrypt.decrypt.test;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class EncryptDecryptDataTestTest {
    @Test
    public void test_in_memory_encryption_decryption() throws Exception {
        // Setup
        EncryptDecryptDataTest rsa = new EncryptDecryptDataTest(
                "./private_key_rsa_4096_pkcs8-exported.pem"
                , "./public_key_rsa_4096_pkcs8-exported.pem"
        );
        String expected = "Text to be encrypted";

        // Test
        String encryptedAndEncoded = rsa.encryptToBase64(expected);
        String actual = rsa.decryptFromBase64(encryptedAndEncoded);

        // Assert
        Assertions.assertEquals(expected, actual);
    }
}
