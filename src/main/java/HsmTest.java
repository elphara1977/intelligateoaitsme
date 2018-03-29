import org.apache.commons.codec.binary.Base64;
import sun.security.pkcs11.SunPKCS11;
import sun.security.rsa.RSAPadding;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.xml.bind.DatatypeConverter;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Scanner;

import static java.lang.String.format;

public class HsmTest {

    public static void main(String[] args) throws Exception {
        //FOR LUNA
        String configName = "/usr/safenet/luna.cfg";
        //char[] pin = "3C/N-7xWq-bLEF-GEq7".toCharArray();
        char[] pin = "Mb7q-X/AK-GLGA-b9sW".toCharArray();

        // For VAGRANT
        //String configName = "/opt/forgerock/software/softhsm/pkcs11.conf";
        //char[] pin = "123456".toCharArray();

        Provider provider = new SunPKCS11(configName);
        List<String> algos = new ArrayList<String>();
        for (Provider.Service service : provider.getServices()) {
            System.out.println(format("Service Type : %s  ---  Algorithm: %s", service.getType(), service.getAlgorithm()));
            if (service.getType().equalsIgnoreCase("cipher")) {
                algos.add(service.getAlgorithm());
            }
        }
        algos.add("RSA//OAEPWithSHA1AndMGF1Padding");

        System.out.println("provider infos : \n" + provider.getInfo());
        for (Object key : provider.keySet()) {
            System.out.println("key: " + key+ " -> value: "+provider.get(key));
        }
        KeyStore keystore = KeyStore.getInstance("PKCS11", provider);
        String alias = "ditsmeamenc";
        alias = "authsigner";
        Scanner sc=new Scanner(System.in);
        System.out.print("ENTER THE ALIAS ??? ");
        alias=sc.nextLine();

        keystore.load(null, pin);
        System.out.println("keystore : " + keystore.getType());
        Enumeration<String> aliases = keystore.aliases();
        while (aliases.hasMoreElements()) {
            System.out.println("alias -> " + aliases.nextElement());
        }
        Key key = keystore.getKey(alias, pin);
        if (key == null) {
            System.out.println("cannot acces the key !");
            System.exit(1);
        }
        System.out.println("key format : " + key.getFormat());
        System.out.println("key class : " + key.getClass());
        if (key instanceof PrivateKey) {
            if (key instanceof  RSAPrivateKey) {
                RSAPrivateKey pKey = (RSAPrivateKey) key;
                String pKeyStr = Base64.encodeBase64String(pKey.getEncoded());
                System.out.println(format("Pri Key : %s",pKeyStr));
            }

            Certificate cert = keystore.getCertificate(alias);
            RSAPublicKey pubKey = (RSAPublicKey) cert.getPublicKey();
            String pubKeyStr = Base64.encodeBase64String(pubKey.getEncoded());
            System.out.println(format("Pub Key : %s",pubKeyStr));


            byte[] input = "Hello HSM !".getBytes();

            for (String algo : algos) {
                try {
                    Cipher cipher = Cipher.getInstance(algo,provider);

                    System.out.println(format("cipher algorithm : %s", cipher.getAlgorithm()));
                    //System.out.println(format("algo param : %s", new String(cipher.getParameters().getEncoded())));

                    cipher.init(Cipher.ENCRYPT_MODE, pubKey);
                    byte[] crypted = cipher.doFinal(input);
                    System.out.println(format("crypted result : %s", new String(crypted)));

                    cipher.init(Cipher.DECRYPT_MODE, key);
                    byte[] paddedPlainText = cipher.doFinal(crypted);

                    /* Ensure leading zeros not stripped */
                    if (paddedPlainText.length < 2048 / 8) {
                        byte[] tmp = new byte[2048 / 8];
                        System.arraycopy(paddedPlainText, 0, tmp, tmp.length - paddedPlainText.length, paddedPlainText.length);
                        System.out.println("Zero padding to " + (2048 / 8));
                        paddedPlainText = tmp;
                    }

                    System.out.println("OAEP padded plain text: " + DatatypeConverter.printHexBinary(paddedPlainText));

                    OAEPParameterSpec paramSpec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1,
                            PSource.PSpecified.DEFAULT);
                    RSAPadding padding = RSAPadding.getInstance(RSAPadding.PAD_OAEP_MGF1, 2048 / 8, new SecureRandom(), paramSpec);
                    byte[] plainText2 = padding.unpad(paddedPlainText);

                    System.out.println("Unpadded plain text: " + DatatypeConverter.printHexBinary(plainText2));

                } catch (Exception s) {
                    s.printStackTrace();
                }
            }

        }
    }
}
