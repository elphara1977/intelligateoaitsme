import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.provider.LunaProvider;

public class SecurityProviderSample {

    public static final String TRANSFORMATION_NAME_AES = "AES/CBC/PKCS5Padding";
    public static final byte[] INITIALIZATION_VECTOR_AES =
            {(byte) 90, (byte) 90, (byte) 90, (byte) 90, (byte) 90, (byte) 90, (byte) 90, (byte) 90, (byte) 90, (byte) 90, (byte) 90, (byte) 90,
                    (byte) 90, (byte) 90, (byte) 90, (byte) 90};

    public static void main(String[] args) {

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
            slotManager.login("is@b3l20");

            // Generate random data
            byte[] l_rand = new byte[8];
            SecureRandom secureRandom = SecureRandom.getInstance("LunaRNG");
            secureRandom.nextBytes(l_rand);

            System.out.println("8 bytes random generated: " + javax.xml.bind.DatatypeConverter.printHexBinary(l_rand));

            // keystore
            KeyStore l_ks = KeyStore.getInstance("Luna", "LunaJCAProvider");
            l_ks.load(null);

            if (l_ks.isKeyEntry("MobileKey")) {
                SecretKey l_key = null;
                byte[] l_enc_data;
                byte[] l_dec_data;
                String l_data = "12345";

                l_key = (SecretKey) l_ks.getKey("MobileKey", null);
                System.out.println("Using key MobileKey=" + l_key.getFormat() + " algo=" + l_key.getAlgorithm() + " : Handle="
                        + Arrays.toString(l_key.getEncoded()));

                // Encrypt data using a specific initialization vector
                IvParameterSpec ivspec = new IvParameterSpec(INITIALIZATION_VECTOR_AES);

                Cipher cph = Cipher.getInstance(TRANSFORMATION_NAME_AES);
                cph.init(Cipher.ENCRYPT_MODE, l_key, ivspec);
                l_enc_data = cph.doFinal(l_data.getBytes());

                System.out.println("data: " + l_data);
                System.out.println("Encrypted data: " + javax.xml.bind.DatatypeConverter.printHexBinary(l_enc_data));

                Cipher decrypt = Cipher.getInstance(TRANSFORMATION_NAME_AES);
                decrypt.init(Cipher.DECRYPT_MODE, l_key, ivspec);
                l_dec_data = decrypt.doFinal(l_enc_data);

                System.out.println("Decrypted data: " + new String(l_dec_data));

            } else {
                System.out.println("MobileKey not found");
            }

            slotManager.logout();
        } catch (ProviderException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
