package my.test.verify;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.junit.jupiter.api.Assertions;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class KeyPairValidationTest {

    /**
     * The purpose of this code will be to verify that a public/private keypair is a match.
     *
     * Illustrates understanding of basic concepts of keys and certificate encodings, and signing an object
     * with a private key then verifying the signature with the certificate.
     *
     * Where the default javax.crypto API support is insufficient, Bouncycastle libraries should be used as they
     * provide comprehensive cryptographic operations support.  Please provide the code with a gradle
     * build file including the necessary dependencies so it can be built and executed
     *
     * This should be done for both ECC and RSA.  A set of matching key/certificates for each are included below.
     *
     * Bonus: sign and verify some data on the command line with openssl
     *
     *
     */




    public static void main(String[] args) throws Exception {

        String eccCert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIB+zCCAVygAwIBAgIJALtuvIUD5bGXMAoGCCqGSM49BAMCMBcxFTATBgNVBAMM\n" +
                "DFBDLUVDQ0EtVEVTVDAeFw0yMjA4MTIxNzI5MDNaFw0yMzA4MTIxNzI5MDNaMBYx\n" +
                "FDASBgNVBAMMC2JvYjI1Ni1zY2VwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n" +
                "o3Vi+2gwxCT2tAwj2Bt+mbUCsPhHbCJ3Vr5hoaLnbxhlhSXH0Td5y9Oo0TTR7WhD\n" +
                "oNK+J7GNIBKrulqs91fxraOBkTCBjjAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQM\n" +
                "MAoGCCsGAQUFBwMCMEcGA1UdIwRAMD6AFKZY0YHqqCRrgCinhhOFUCajKY3moRuk\n" +
                "GTAXMRUwEwYDVQQDDAxQQy1FQ0NBLVRFU1SCCQC1EJLK4Qp9TTAdBgNVHQ4EFgQU\n" +
                "WrJTjTiq+AKpuEdR4mmcbS17/GIwCgYIKoZIzj0EAwIDgYwAMIGIAkIAmormONWJ\n" +
                "R/ii9SXvEEXGPKVIcz7yaWRItQAWTH9AuSQbOVKhZ+hLli8JyxmaJl8CaMnEPu8+\n" +
                "2y/IVG3eBKDF0bQCQgGZXF2E5aLn6KheJGoEYLhnlXS9e58K4xmDcn4Lwj5Ti8sX\n" +
                "uI9PjBsaNoBSq8LmdAQrMOO2wZRPdqyJJ2efBsIsGQ==\n" +
                "-----END CERTIFICATE-----";

        String eccKey = "-----BEGIN EC PRIVATE KEY-----\n" +
                "MHcCAQEEIJIPHQlxeLbIYWopuWtVDdQhCP3rcYr1LWm4xv7wBPy1oAoGCCqGSM49\n" +
                "AwEHoUQDQgAEo3Vi+2gwxCT2tAwj2Bt+mbUCsPhHbCJ3Vr5hoaLnbxhlhSXH0Td5\n" +
                "y9Oo0TTR7WhDoNK+J7GNIBKrulqs91fxrQ==\n" +
                "-----END EC PRIVATE KEY-----";




        String rsaCert = "-----BEGIN CERTIFICATE-----\n" +
                "MIICmjCCAYICCQCe7/hdRJT7hDANBgkqhkiG9w0BAQsFADANMQswCQYDVQQDDAJj\n" +
                "YTAeFw0yMjA4MjQxNzA4MDJaFw0yMzA4MTkxNzA4MDJaMBExDzANBgNVBAMMBmNs\n" +
                "aWVudDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOHoWGRoEJy8oj+S\n" +
                "X++vNU7jC3EBaDSH7sTKAYDo/T7+1v0oQZA0r4V6XXDiUV/GmYSwCZAijjR+8DPF\n" +
                "pDY2HFcawyNHtHYWYc35nouNlpnnFGEI6iEilHxh0xPUnaiDfMKv1DHB6QkV6Y2s\n" +
                "uQ1XTyJ2b4PA0f4x4dj1si4AncF48swoAMQg54iMD+omzjC8r9pFs4BjgeG9G/rL\n" +
                "Y51FJ7dubhk6SAKJsoEGwFbJg1Pq/k8ESGnOadavySJljoue4b+CIGrSWis5f5up\n" +
                "CmZk9NZu0nW3QdcPZtesGYYR6lRatDWb762QJYKikvw45oyQkYGHMIQOO7URgZUL\n" +
                "8qPO1L8CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAjtTgCBGUIwLIX/H8kOxweH5P\n" +
                "ItRU4y7q3oU1bD11NimuzM2THJDR/qni3/T2vkjnVJMRbTdYwBnoT8edujxl3321\n" +
                "yxCsRgFeEHgHwq74m7KsBDAf7B7fxypHUzshp2H+W3BQLdaFKVSvX6VomMwE8fF7\n" +
                "BXR+nCQQM/ZWl/OsNFswsDI49htCoQzKM5h9MjIIm/IJr3oyRYubf+aFlq3o/hsh\n" +
                "GwZqLkJMHOVPvFTupxhoOElACn6MkwXKmtuA18SDStRrJWSJo1GXMIHUmpbCggjw\n" +
                "Sc0wDOX91NDxYafuAUgaEzrS6saSjl/b/Qn+SZrJBSqmEHx4PWszYmW1H3rCzQ==\n" +
                "-----END CERTIFICATE-----\n";

        String rsaKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIIEpQIBAAKCAQEA4ehYZGgQnLyiP5Jf7681TuMLcQFoNIfuxMoBgOj9Pv7W/ShB\n" +
                "kDSvhXpdcOJRX8aZhLAJkCKONH7wM8WkNjYcVxrDI0e0dhZhzfmei42WmecUYQjq\n" +
                "ISKUfGHTE9SdqIN8wq/UMcHpCRXpjay5DVdPInZvg8DR/jHh2PWyLgCdwXjyzCgA\n" +
                "xCDniIwP6ibOMLyv2kWzgGOB4b0b+stjnUUnt25uGTpIAomygQbAVsmDU+r+TwRI\n" +
                "ac5p1q/JImWOi57hv4IgatJaKzl/m6kKZmT01m7SdbdB1w9m16wZhhHqVFq0NZvv\n" +
                "rZAlgqKS/DjmjJCRgYcwhA47tRGBlQvyo87UvwIDAQABAoIBAQC9a7zyM+/5/JFv\n" +
                "DKU0rIzeYLIvRybBJVmn2Fn6ZWIzeCt8ikyvRf4Gxduj06C31ibTg2gBW3gxvF5c\n" +
                "itRuQGDzCJWm93Dxs0K/Gxc9nLMyyPflhTwMHJq00LHUZurraZUrCZO7RQTJgX4c\n" +
                "NT/VV+ga1YQbzYpGwjzFVv7YY9vjZJtHop3MrWNmufjnAxmY4e/mHNbBWdhr4iUG\n" +
                "89owqWWsbCI8JLDeCTz1Dpd/IOSdeDVJpHGTsu3Ut2JCIJ06D5mevG3edE0kzybU\n" +
                "sC5d5rywbYCy2nqAxiGyEGejd/a696qVqqQqxCtH6uG4AMNsCRItlGPMqQ/8swaZ\n" +
                "j9akK6YBAoGBAPsIU22P423kzlxYr2246lW8+QrjkhIJwm+sdMkETqFKE5wiesN/\n" +
                "8hY6pYYGETZ6xR2QmPNYzr6gMYqItFXarP9Ew+Cp4YYrVajw2g+C8Ixk8EfkBQw6\n" +
                "9XsAz5DakfO4lq3MPcjpUi75TyqmDMCIRrOs3nzTdhWgnRofoksJnjXfAoGBAOZg\n" +
                "vgCEWnhQ545eidJ0fQCrPA0inFIKBPR9oOAex2NBaAUFXM5m0S1LzfULBnkOiCSj\n" +
                "nWgcMhYjktJdTaRZOoq4D0AJ1B1D2TMwH7o8ZEu2gY4Ika+c6xAQUf9acR67v/lh\n" +
                "QY7CQ+Xbsth3G0l5cOU3WorpqukeUSHkvf5FZH0hAoGBAKIFlqtBUn3sTtDFoLyF\n" +
                "vCGIbYj8ppuj1u3y9hGECSgKwqtkia3C18JHKexd4CA0jyLs3/s4V4Arrq4GW7aK\n" +
                "BFxhyrcnjlrlf00h3uxiC9XhlEAiSKvDJgu000Nf/xG6Eu6rwzj4dsXAvbr+H37o\n" +
                "thFjwtn4Nd/xoVRqFHqwA4ArAoGBAL7AK5JSBHbKxm/jZ0qSmU4MelSF69kh4qht\n" +
                "vN7VnVJZvb8qiYV9LIXM1mOnFVz241MzBgpGDlK2ccMs7jS+jPJ/JGFpwe/ZVeZE\n" +
                "WoDhsEnge7UW80ntK9TJLpu4TyGbY4EhPh7uSznvh04kkLttikTAaH/Mqm8LYzIl\n" +
                "LAt1eZcBAoGAFK+RC5AkQvbr5edQY7EpbazF722k+w+qcSkr0+qV/hWc2xgKNrb4\n" +
                "25dTrxuAObXycRum47JzVp0DC/SU4qCp4VZiB+QcJ82hcxk5GTef+wVNlcgHRUZw\n" +
                "vtXy0n15fuXske/MaFrh4z4n/Ie62+wbPRBk8mkVIOxsFhYfdpcldrA=\n" +
                "-----END RSA PRIVATE KEY-----\n";




        Assertions.assertTrue(verifyKeyAndCert(eccCert,eccKey));


        Assertions.assertTrue(verifyKeyAndCert(rsaCert,rsaKey));

    }


    public static boolean verifyKeyAndCert(String pemEncodedCert, String pemEncodedKey) throws Exception {

        //create PrivateKey and X509Certificate objects
        PrivateKey privateKey = readPrivateKey(pemEncodedKey);
        //create a Signature object
        X509Certificate certificate = readX509Certificate(pemEncodedCert);

        Signature signature = Signature.getInstance(certificate.getSigAlgName());

        //sign some bytes
        byte[] messageBytes = "Any String".getBytes();
        byte[] signedBytes = signData(signature, privateKey, messageBytes);

        //verify the signature using the certificate
        signature.initVerify(certificate.getPublicKey());
        signature.update(messageBytes);
        boolean isItValid = signature.verify(signedBytes);

        System.out.println(certificate.getSigAlgName() + " Signature "+ isItValid);
        return isItValid;
    }

    private static PrivateKey readPrivateKey(String pemEncodedKey)
            throws IOException {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        PEMParser pemPKParser = new PEMParser(new StringReader(pemEncodedKey));
        PEMKeyPair keyPair = (PEMKeyPair) pemPKParser.readObject();
        PrivateKey prik = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getKeyPair(keyPair).getPrivate();
        return prik;
    }

    private static X509Certificate readX509Certificate(String pemEncodedCert) throws CertificateException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(pemEncodedCert.getBytes()));
    }

    private static byte[] signData(Signature signature, PrivateKey privateKey, byte[] messageBytes) throws InvalidKeyException, SignatureException {
        signature.initSign(privateKey);
        signature.update(messageBytes);
        return signature.sign();
    }

}
