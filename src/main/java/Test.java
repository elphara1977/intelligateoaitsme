import com.nimbusds.jose.jwk.RSAKey;
import com.safenetinc.luna.provider.LunaProvider;
import org.bouncycastle.crypto.KeyParser;
import org.bouncycastle.jcajce.provider.util.SecretKeyUtil;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Test {

    public static void main0(String[] args) throws Exception {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        final KeyPair keyPair = keyGen.generateKeyPair();

        byte[] sourceText = "Hello HSM".getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        byte[] encryptedText = cipher.doFinal(sourceText);
        System.out.println(String.format("cipher : %s", Base64.getEncoder().encodeToString(encryptedText)));

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        byte[] decryptedText = cipher.doFinal(encryptedText);
        System.out.println(String.format("clear : %s", new String(decryptedText)));
    }

    public static void main1(String[] args) throws Exception {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        final KeyPair keyPair = keyGen.generateKeyPair();
//        X509Certificate cert = X509CertUtils.parse(Base64.getDecoder().decode("MIIE4TCCAsmgAwIBAgIGIBgIYAEBMA0GCSqGSIb3DQEBCwUAMD8xCzAJBgNVBAYTAkJFMQ4wDAYDVQQDDAVDQSA0SzELMAkGA1UECgwCQ0ExEzARBgNVBAcMCklTQUJFTEJFVEEwHhcNMTgwMzI3MDAwMDAwWhcNMzExMjAzMjM1OTU5WjBSMQswCQYDVQQGEwJCRTETMBEGA1UEBxMKSXNhYmVsQmV0YTENMAsGA1UEChMEVEVTVDEMMAoGA1UECxMDUEtJMREwDwYDVQQDDAh0ZXN0X2tleTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKwQVYFGmXtPPxP7lAKe6zpFTmXgU1490MxpS0bqIRrPs3fOTrIdOqC6wpx4AFblaQIRY0pod5kYZ07btJ2U4DhrWizS66AnOQx44HEF0YMGE6xHDNm4kFW4b/O4kF+pI6YubH8yiGvL1BeI/M1UdlJJwZlPZKridgb1PANG3JmOxkaE0E4LtVKWpVWEkyO0q3AkxEULFyRGc1Tukn6qRdrzGQWqPjdN4ZtcacHhyqvvIrWtXWzdgr5XVgyx+pMigyxBddPtquvWR6OAKrUMTQAf8m0mQpDiNdTqRb5I1v1CCObnxPOCKhkJJLbs7uNU0pgWEtQGvWtfUP1FzzEbzY8CAwEAAaOBzzCBzDAfBgNVHSMEGDAWgBSMS2x+rktE02LXbuCcuXB9UEaIZDBIBgVgOAEIAQQ/MD2AHVY6QTpOOjA6Q29weXJpZ2h0IElzYWJlbCAyMDE4gQ0wMDAwMDAwMDAwMTAxgg01MDAwMDM1OTAyNTc5MDsGCCsGAQUFBwEBBC8wLTArBggrBgEFBQcwAYYfaHR0cHM6Ly9wa2kuZGV2LmlzYWJlbC5iZS9vY3NwMjALBgNVHQ8EBAMCBPAwFQYDVQQFBA4TDDcwMDAwMDAxMjM3MDANBgkqhkiG9w0BAQsFAAOCAgEACFtVapgCmuPAn7nSB9Td0wPLgSfvd4E7Ka4eZyH2KsWTPbJUgZcT42Odhmg2lInO3lctRiomUs7X9hfhcBwuNFFBi6Io7qpPHDyi8MX/4eEGPJEAuxSoUKKFQ4q+pRDsB3gok0IaRB6ZNyZg6WDGikgIGBhM99Uo6ZKsxy8Y+h9Bp5EhH3xgZjtiMX0mAOjC7xrXt9kZnSVQpMSuOD4b5e58tg5RlCCesBJfMni8NpY3NR7gvPS/0k+fabWXKy4rMOVdI/qd4x6ZwwDgV0C9l2P26wR5RRD0iFikpbA7ABK1smZDt7VnxaKHwa53E1ehCo2Xx4caq/88JdbGA+IZoG5d3gn/t8Yakh4rhNt05RO73jCxvU8Lb96yKN1q2MOFHmBkPV0Kr7GCV4sl8u/0bT1m+UYS7gWk1Pa0Cnuv85lIJx9NAjqz9rSKGjyHseUYI02k15AiCVunET11lD3oaFGxN8NkKMW8pKrPD3D4DRvEqZpVf9rwWSjNUby3vvf9vAqGDwm91Lt89rdsKd7PsfSgfehdPiKEkzvQHe5xc1J5OIO9jayny6qwGLwZUMPSiS4Q560gojHUf9iMyHz8goddsqsSvRx13V/+paunL+nRxSY5N4y5XSd8xoTwHJk64PXixqbsY/+t4uuijbcno0Rb86203KlrgYSfYmQhrio="));
//        System.out.println("cert=" + cert);
        byte[] sourceText = "Hello HSM".getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
//        cipher.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
        System.out.println("pub=" + keyPair.getPublic());
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        byte[] encryptedText = cipher.doFinal(sourceText);
        System.out.println(String.format("cipher : %s", Base64.getEncoder().encodeToString(encryptedText)));

        System.out.println("prv= " + Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        byte[] decryptedText = cipher.doFinal(encryptedText);
        System.out.println(String.format("clear : %s", new String(decryptedText)));
    }

    public static void main(String[] args) throws Exception {
        LunaProvider provider = new LunaProvider();
//        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", provider);
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        final KeyPair keyPair = keyGen.generateKeyPair();
//        X509Certificate cert = X509CertUtils.parse(Base64.getDecoder().decode("MIIE4TCCAsmgAwIBAgIGIBgIYAEBMA0GCSqGSIb3DQEBCwUAMD8xCzAJBgNVBAYTAkJFMQ4wDAYDVQQDDAVDQSA0SzELMAkGA1UECgwCQ0ExEzARBgNVBAcMCklTQUJFTEJFVEEwHhcNMTgwMzI3MDAwMDAwWhcNMzExMjAzMjM1OTU5WjBSMQswCQYDVQQGEwJCRTETMBEGA1UEBxMKSXNhYmVsQmV0YTENMAsGA1UEChMEVEVTVDEMMAoGA1UECxMDUEtJMREwDwYDVQQDDAh0ZXN0X2tleTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKwQVYFGmXtPPxP7lAKe6zpFTmXgU1490MxpS0bqIRrPs3fOTrIdOqC6wpx4AFblaQIRY0pod5kYZ07btJ2U4DhrWizS66AnOQx44HEF0YMGE6xHDNm4kFW4b/O4kF+pI6YubH8yiGvL1BeI/M1UdlJJwZlPZKridgb1PANG3JmOxkaE0E4LtVKWpVWEkyO0q3AkxEULFyRGc1Tukn6qRdrzGQWqPjdN4ZtcacHhyqvvIrWtXWzdgr5XVgyx+pMigyxBddPtquvWR6OAKrUMTQAf8m0mQpDiNdTqRb5I1v1CCObnxPOCKhkJJLbs7uNU0pgWEtQGvWtfUP1FzzEbzY8CAwEAAaOBzzCBzDAfBgNVHSMEGDAWgBSMS2x+rktE02LXbuCcuXB9UEaIZDBIBgVgOAEIAQQ/MD2AHVY6QTpOOjA6Q29weXJpZ2h0IElzYWJlbCAyMDE4gQ0wMDAwMDAwMDAwMTAxgg01MDAwMDM1OTAyNTc5MDsGCCsGAQUFBwEBBC8wLTArBggrBgEFBQcwAYYfaHR0cHM6Ly9wa2kuZGV2LmlzYWJlbC5iZS9vY3NwMjALBgNVHQ8EBAMCBPAwFQYDVQQFBA4TDDcwMDAwMDAxMjM3MDANBgkqhkiG9w0BAQsFAAOCAgEACFtVapgCmuPAn7nSB9Td0wPLgSfvd4E7Ka4eZyH2KsWTPbJUgZcT42Odhmg2lInO3lctRiomUs7X9hfhcBwuNFFBi6Io7qpPHDyi8MX/4eEGPJEAuxSoUKKFQ4q+pRDsB3gok0IaRB6ZNyZg6WDGikgIGBhM99Uo6ZKsxy8Y+h9Bp5EhH3xgZjtiMX0mAOjC7xrXt9kZnSVQpMSuOD4b5e58tg5RlCCesBJfMni8NpY3NR7gvPS/0k+fabWXKy4rMOVdI/qd4x6ZwwDgV0C9l2P26wR5RRD0iFikpbA7ABK1smZDt7VnxaKHwa53E1ehCo2Xx4caq/88JdbGA+IZoG5d3gn/t8Yakh4rhNt05RO73jCxvU8Lb96yKN1q2MOFHmBkPV0Kr7GCV4sl8u/0bT1m+UYS7gWk1Pa0Cnuv85lIJx9NAjqz9rSKGjyHseUYI02k15AiCVunET11lD3oaFGxN8NkKMW8pKrPD3D4DRvEqZpVf9rwWSjNUby3vvf9vAqGDwm91Lt89rdsKd7PsfSgfehdPiKEkzvQHe5xc1J5OIO9jayny6qwGLwZUMPSiS4Q560gojHUf9iMyHz8goddsqsSvRx13V/+paunL+nRxSY5N4y5XSd8xoTwHJk64PXixqbsY/+t4uuijbcno0Rb86203KlrgYSfYmQhrio="));
//        System.out.println("cert=" + cert);
        byte[] sourceText = "Hello HSM".getBytes();
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
//        cipher.init(Cipher.ENCRYPT_MODE, cert.getPublicKey());
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        byte[] encryptedText = cipher.doFinal(sourceText);
        System.out.println(String.format("cipher : %s", Base64.getEncoder().encodeToString(encryptedText)));



        String privateKeyContent = "AAAAAAAehTI= ";
        privateKeyContent=Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());


        privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");

        KeyFactory kf = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        PrivateKey rk = kf.generatePrivate(keySpecPKCS8);

        String publicKeyContent=Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
        RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);
        System.out.println("pk= "+pubKey);

        System.out.println("rk= "+rk);

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        byte[] decryptedText = cipher.doFinal(encryptedText);
        System.out.println(String.format("clear : %s", new String(decryptedText)));
    }

}