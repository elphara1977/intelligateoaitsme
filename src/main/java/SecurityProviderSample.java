import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.util.*;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.provider.LunaProvider;
import com.safenetinc.luna.provider.key.LunaKey;
import com.safenetinc.luna.provider.key.LunaPrivateKeyRsa;

public class SecurityProviderSample {

    public static final List<String> TRANSFORMATION_NAME_OAEP = new ArrayList();


    public static void main(String[] args) {

        /*TRANSFORMATION_NAME_OAEP.add("RSA/None/OAEPWithSHA1AndMGF1Padding");
        TRANSFORMATION_NAME_OAEP.add("RSA/ECB/OAEPWithSHA256AndMGF1Padding");
        TRANSFORMATION_NAME_OAEP.add("RSA/None/OAEPWithSHA256AndMGF1Padding");
        TRANSFORMATION_NAME_OAEP.add("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        TRANSFORMATION_NAME_OAEP.add("RSA/None/OAEPWithSHA-256AndMGF1Padding");
*/
        Security.addProvider(new LunaProvider());

        for (Provider provider : Security.getProviders()) {
            System.out.println("Provider: " + provider.getName() + " version: " + provider.getVersion());
            for (Provider.Service service : provider.getServices()) {
                System.out.printf("  Type : %-30s  Algorithm: %-30s\n", service.getType(), service.getAlgorithm());
            }
        }
        System.out.println();

        LunaSlotManager slotManager = LunaSlotManager.getInstance();
        try {
            slotManager.login("assyslunaHA_part1", "3C/N-7xWq-bLEF-GEq7");

            // Generate random data
            byte[] l_rand = new byte[8];
            SecureRandom secureRandom = SecureRandom.getInstance("LunaRNG");
            secureRandom.nextBytes(l_rand);

            System.out.println("8 bytes random generated: " + javax.xml.bind.DatatypeConverter.printHexBinary(l_rand));

            // keystore
            KeyStore l_ks = KeyStore.getInstance("Luna", "LunaProvider");
            l_ks.load(null, null);
            /**Enumeration<String> aliases = l_ks.aliases();
             while (aliases.hasMoreElements()) {
             String s =  aliases.nextElement();
             System.out.println("Existing alias : "+s);
             java.security.Key l_key = l_ks.getKey(s, "Mb7q-X/AK-GLGA-b9sW".toCharArray());
             if (l_key != null) {
             System.out.println("Using key "+s+"=" + l_key.getFormat() + " algo=" + l_key.getAlgorithm() + " : Handle="
             + Arrays.toString(l_key.getEncoded())+" class :"+l_key.getClass());
             } else {
             LunaKey pk = LunaKey.LocateKeyByAlias("aitsmeamenc_pub");
             if (pk != null) {
             System.out.println("Using key "+s+"=" + pk.getFormat() + " algo=" + pk.getAlgorithm() + " : Handle="
             + Arrays.toString(pk.getEncoded())+" class :"+pk.getClass());
             }
             }
             }*/

            if (l_ks.containsAlias("ditsmeamenc")) {
                LunaPrivateKeyRsa l_key = null;
                byte[] l_enc_data;
                byte[] l_dec_data;
                String l_data = "12345";

                LunaKey pk = LunaKey.LocateKeyByAlias("ditsmeamenc_pub");

                l_key = (LunaPrivateKeyRsa) l_ks.getKey("ditsmeamenc", "3C/N-7xWq-bLEF-GEq7".toCharArray());
                System.out.println("Using key aitsmeamenc=" + l_key.getFormat() + " algo=" + l_key.getAlgorithm() + " : Handle="
                        + Arrays.toString(l_key.getEncoded()));
                
                     try {

                        String encryptedJWT = "eyJ0eXAiOiJKV1QiLCJraWQiOiJjOEhpc3hRenNBKytpYWVSeWx0YlVUK2NkbDA9IiwiY3R5IjoiSldUIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImFsZyI6IlJTQS1PQUVQIn0.evHa5fM7yUusIEazUvBdTPBgdyJNI0h3J3ROPw-xSJIAtMe8y6aWzb09bSwcynH2U2IhLGu_vVvKpeEHHFV6PRw8lecgY7Ik_VOmb6t-uzyjpUr56i_6iY3jyvDVL5QOe4E2Lkocg-v3dAL73GEpIKU2lK-wYQtT3qKYtNdLL-QnTyM-Ub6uXkEG05maXCTGHR1CF2GNluWClIaNRhWpQ-FaDmeAEAYX1ZRnmlo423DpGXYAs6z5gSPZcPsCDg0SWXwf-AcOMCdGPp8NBCfDbqKE1qpgUELSbBSgYGM8lddOV9StA4j469Rc9WzHuqSlTSHmcCt6c8mcV_kUVBVtrw.1qZAcjLOWzX1D-fJU_UDwg.bNe4fLnczKdLIbWey104CCsvr6XlS2WZFjx-g1eHI8AQfMdGKZ0dLkUv_jLRs7INemMABcrbGUK8rBpCIsqt1TvDzMEzMUBZ96_tZbq0sdtsUCFF_14VAzgHhTOGeZ9C1w8gro1NjFsCpx9M4P9SOH3GStUOMSI7XQfOxH8IrR_DpiPk7IlzeV7ob1oIrtLluKhQZdqT2yzoKMIAyM8jSP1jDIh4591QQTJZB1uW35eP4fKbiUfZExwONosU32Y3J0irqywK9bwmKpAa_HJTr4-G7-noa3a-r7V02pxh6HX-yVtucrM9M0vX73lemNvWIh7ZaBuWcMWpwTvg4FDqrnSvau_t20-25hoAWMwSjD20GYxaPGF4Ri8ekT2EbAOZVrlKlLuM9WktLAXR9AXDUGWRyS8wkpaOydwtHO_tc4kga1tFFp74XCDvOou_po_56DSWDQiaOW8Q9SoIh64yBqgFtzSTZX2b8esWTHAmDxbe8-5GwMxSwGg2_C4xn1TUAW2l6DBOqpaZy4aX8h9Y5kymRjuQ19JXAH7fCYk3SiqfTcKte-TfSQtaCpB2_5WddzH8qstuzrPyKDTzxv0N4lYVrFNFdb-CKuLGKXpSGKdWlO-8aFgYLAEdndbOo_kEGSzxu8_7GZEuI-FHT7gW1pYYhUr6HaJjsgpH_8N-XRpx0uF1a3ZrqwAh-MmbT3z4SZ7KsnN1LkR_H6qz6w7aigtRf1XiuyBJX0X1RPnxhjWTyBS3u6UFowYxvvW74vj67P_LlpDcXHMxdBIiBC8hWN2Fcq2mh4pZmJmTxCoTkReU-rvszYxC7NWLgk4c3bi5VcmWXGHHEKU0QKJvOgmLsPFj5MDqh7uUiDsLoPfZCk3cTsmIiI6maBroFa9Y_jFJUZZehGLx0c8r5_55LrPJuxKr939P6meiuFq8eWmOOicIT7y-tdJ0uOlncY6tmCPu1omrb32g2vvqB0aPZQGKsFyDfUB1nquLGegmLKbDg_Vyzirzg_G4wzP24ZLHNPzv7Wh3uOnYT4CIu4-nqHT48-MmoeupGPDxOk1hZXB348LJp1_1sNdbIeforbULYQEFt6wnyvXRv3NhJmJZkKusAVReKRv6UiG5qMXIVwTTsK4c6GHv64TcBj_uqCWXhO1SEZkdjijf4HTG5LDetbT0-2SO7cxHxMgzH8JGgGpUkfU.MMnfMTg71imPNRr-Jugi4Q";
                        EncryptedJWT ejwt = EncryptedJWT.parse(encryptedJWT);

                        // Create a decrypter with the specified private RSA key
                        RSADecrypter decrypter = new RSADecrypter(l_key);
                        ejwt.decrypt(decrypter);

                        System.out.println("decrypted jwt:"+ejwt.getPayload().toString());
                        SignedJWT sjwt = SignedJWT.parse(ejwt.getPayload().toString());
                        System.out.println("Claims:"+sjwt.getJWTClaimsSet().toString());
/**
                        String initVectVal = "NVj5yQhXcYPKlH8ejILC0w";

                        byte[] initializationVector = Base64.getUrlDecoder().decode(initVectVal);;

                        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
                        Cipher cph = Cipher.getInstance(algo, "LunaProvider");
                        cph.init(Cipher.ENCRYPT_MODE, pk, oaepParams);
                        l_enc_data = cph.doFinal(l_data.getBytes());

                        System.out.println("data: " + l_data);
                        System.out.println("Encrypted data: " + javax.xml.bind.DatatypeConverter.printHexBinary(l_enc_data));




                        String cipheredPart = "8Q_LWRxOIzckeeyspL-3GGK5WhhY-XWhXyQu128W8dCgwnsI3-u0gPCaXfuR0NpmwusVMSUs7KfhCtlbbsE-3GjVtw9Jlr2_OovwHpg-2BTp-N8CBhaJi5UXIj-s_lcUxPQB4inVWtvWxjv1Q7D96RuY9vaCWhzSdcgFm7x2KuZdl4ae7W9d0gZDsngPAsGrsmcxZzTslWLrYNJx4D9tnlXzNNysc0XFB-X-7Ww2NSubkgLd9YBCULTXxRjCowBz4P3qu2OOebmb5MFXDADF_ANRWK4jqp2kX236AFhfnrjBd10uKTZPmG4vx10y1BWE9Vo_UyT97uWLxCGMb2o-7VFg5uYQ5ld7tVOnNJeS0sqanJ5iMBn7jb-gghB3uZuHvzofD1GUqr1aTo2I5iJ1HpDGeHNs_VM2nPM0tUERIEVYXwQcwFbnMAqaHaTprS4pMyHz6t2sdNZ0SV1dbNR3qu5jb2_FYWskBWKjOX0Vxkg0TaXr5KZ3MVZIM0NGtU5B200sKrS4TZR8ah6-86emA872RJik-Y8MCYzwIMfucRyZN-klleYD5SSE8Z_tYZ1J54GAYGnJmonMpz0Z_j9J8pxidX9RFLeEfRzKwunGf9AyJkUnhrJge7un7t7hkD8gDheB2aIaD6EZCrhR6R3cs-KRebJX-Z88pI4EFmNrJptyrxW2GQ7FKhe01HEp6EALH9HAMzjh3lxEnkauVHSX1y8Hw5CWonTx7S50sKolllkpOrmcqaAjhWveOZ4-CXWkHkaBT9FkOmFIknYVT7lSvBpsr7DzyU097PW8N8Jf5Hl9xm0XU0kNLV3X6gv6iddCjfEOJ174LQMXhiOdtItqqahyfitx5xXV24P3yhktRxbCry0zUdjBBOQzKq3x8mVs2T8vDxKaoVKxsPNbaEvwp2FrU0IHWYdo4yL_ZgtH5e9DV-sHUDrZBHCsBcbw2uGEGC1SwMXf3BXxe5Z9p2z-RTyv374P2p8GZ_xKTiKWspIq7CSKK_ksqM2rAEaMbltnlgApEXg0GRhnvZIh5AXnwpdy7FovfxHqf6zA9eUgfLM9yjtkrbYfpx82KSTOHhlN12J3CX4WXvnPydg8GvyvkYIJkooxIZNEfSWKUa-d3zG6qMKhlfwnwMNTIwhDoVkovD9O2WAqkrpJj_Y-0lHoGGDp1VH5JKjbc8QBx0xIMKKk5yRXk_IX3pIaJyMg-IfjBwtWK3jJZ1RSHasnG0MHihlro2ap4w_t4kBtJDC7n03uZ0MnbWGhy053L6TydWftY2N-R_QeXil1Tgko9j2Yo-VZ40H0hw2mDcVGTtlAZjuCqJiERueqQDOd5vF6p56t23bLQ0aOGPXFt_FW1dAHrw";
                        byte[] encodedbt = Base64.getUrlDecoder().decode(cipheredPart);
                        System.out.println("Encoded data "+javax.xml.bind.DatatypeConverter.printHexBinary(encodedbt));

                        Cipher decrypt = Cipher.getInstance(algo, "LunaProvider");
                        decrypt.init(Cipher.DECRYPT_MODE, l_key, oaepParams);

                        l_dec_data = decrypt.doFinal(l_enc_data);

                        System.out.println("Decrypted data: " + new String(l_dec_data));

                        l_dec_data = decrypt.doFinal(encodedbt);

                        System.out.println("Decoded data: " + new String(l_dec_data));
*/
                    } catch (Exception t) {
                        t.printStackTrace();
                    }

            } else {
                System.out.println("MobileKey not found");
            }

            slotManager.logout();
        } catch (ProviderException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
