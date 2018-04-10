import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.provider.LunaProvider;
import com.safenetinc.luna.provider.key.LunaPrivateKeyRsa;

import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

public class SecurityProviderSample {

    public static final List<String> TRANSFORMATION_NAME_OAEP = new ArrayList();


    public static void main(String[] args) {

        Security.addProvider(new LunaProvider());

        LunaSlotManager slotManager = LunaSlotManager.getInstance();

        try {
            slotManager.login("assyslunaHA_part1", "3C/N-7xWq-bLEF-GEq7");

            // keystore
            KeyStore l_ks = KeyStore.getInstance("Luna", "LunaProvider");
            l_ks.load(null, null);

            if (l_ks.containsAlias("ditsmeamenc")) {
                LunaPrivateKeyRsa l_key = (LunaPrivateKeyRsa) l_ks.getKey("ditsmeamenc", "3C/N-7xWq-bLEF-GEq7".toCharArray());

                String encryptedJWT = "eyJ0eXAiOiJKV1QiLCJraWQiOiJjOEhpc3hRenNBKytpYWVSeWx0YlVUK2NkbDA9IiwiY3R5IjoiSldUIiwiZW5jIjoiQTEyOENCQy1IUzI1NiIsImFsZyI6IlJTQS1PQUVQIn0.evHa5fM7yUusIEazUvBdTPBgdyJNI0h3J3ROPw-xSJIAtMe8y6aWzb09bSwcynH2U2IhLGu_vVvKpeEHHFV6PRw8lecgY7Ik_VOmb6t-uzyjpUr56i_6iY3jyvDVL5QOe4E2Lkocg-v3dAL73GEpIKU2lK-wYQtT3qKYtNdLL-QnTyM-Ub6uXkEG05maXCTGHR1CF2GNluWClIaNRhWpQ-FaDmeAEAYX1ZRnmlo423DpGXYAs6z5gSPZcPsCDg0SWXwf-AcOMCdGPp8NBCfDbqKE1qpgUELSbBSgYGM8lddOV9StA4j469Rc9WzHuqSlTSHmcCt6c8mcV_kUVBVtrw.1qZAcjLOWzX1D-fJU_UDwg.bNe4fLnczKdLIbWey104CCsvr6XlS2WZFjx-g1eHI8AQfMdGKZ0dLkUv_jLRs7INemMABcrbGUK8rBpCIsqt1TvDzMEzMUBZ96_tZbq0sdtsUCFF_14VAzgHhTOGeZ9C1w8gro1NjFsCpx9M4P9SOH3GStUOMSI7XQfOxH8IrR_DpiPk7IlzeV7ob1oIrtLluKhQZdqT2yzoKMIAyM8jSP1jDIh4591QQTJZB1uW35eP4fKbiUfZExwONosU32Y3J0irqywK9bwmKpAa_HJTr4-G7-noa3a-r7V02pxh6HX-yVtucrM9M0vX73lemNvWIh7ZaBuWcMWpwTvg4FDqrnSvau_t20-25hoAWMwSjD20GYxaPGF4Ri8ekT2EbAOZVrlKlLuM9WktLAXR9AXDUGWRyS8wkpaOydwtHO_tc4kga1tFFp74XCDvOou_po_56DSWDQiaOW8Q9SoIh64yBqgFtzSTZX2b8esWTHAmDxbe8-5GwMxSwGg2_C4xn1TUAW2l6DBOqpaZy4aX8h9Y5kymRjuQ19JXAH7fCYk3SiqfTcKte-TfSQtaCpB2_5WddzH8qstuzrPyKDTzxv0N4lYVrFNFdb-CKuLGKXpSGKdWlO-8aFgYLAEdndbOo_kEGSzxu8_7GZEuI-FHT7gW1pYYhUr6HaJjsgpH_8N-XRpx0uF1a3ZrqwAh-MmbT3z4SZ7KsnN1LkR_H6qz6w7aigtRf1XiuyBJX0X1RPnxhjWTyBS3u6UFowYxvvW74vj67P_LlpDcXHMxdBIiBC8hWN2Fcq2mh4pZmJmTxCoTkReU-rvszYxC7NWLgk4c3bi5VcmWXGHHEKU0QKJvOgmLsPFj5MDqh7uUiDsLoPfZCk3cTsmIiI6maBroFa9Y_jFJUZZehGLx0c8r5_55LrPJuxKr939P6meiuFq8eWmOOicIT7y-tdJ0uOlncY6tmCPu1omrb32g2vvqB0aPZQGKsFyDfUB1nquLGegmLKbDg_Vyzirzg_G4wzP24ZLHNPzv7Wh3uOnYT4CIu4-nqHT48-MmoeupGPDxOk1hZXB348LJp1_1sNdbIeforbULYQEFt6wnyvXRv3NhJmJZkKusAVReKRv6UiG5qMXIVwTTsK4c6GHv64TcBj_uqCWXhO1SEZkdjijf4HTG5LDetbT0-2SO7cxHxMgzH8JGgGpUkfU.MMnfMTg71imPNRr-Jugi4Q";
                EncryptedJWT ejwt = EncryptedJWT.parse(encryptedJWT);

                // Create a decrypter with the specified private RSA key
                RSADecrypter decrypter = new RSADecrypter(l_key);
                ejwt.decrypt(decrypter);

                System.out.println("decrypted jwt:" + ejwt.getPayload().toString());
                SignedJWT sjwt = SignedJWT.parse(ejwt.getPayload().toString());
                System.out.println("Claims:" + sjwt.getJWTClaimsSet().toString());

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
