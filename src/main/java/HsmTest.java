import org.apache.commons.codec.binary.Base64;
import sun.security.pkcs11.SunPKCS11;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;
import java.util.Scanner;

import static java.lang.String.format;

public class HsmTest {

    public static void main(String[] args) throws Exception {
        String configName = "/usr/safenet/luna.cfg";

        Provider provider = new SunPKCS11(configName);

        for (Provider.Service service : provider.getServices()) {
            System.out.println(format("Service Type : %s  ---  Algorithm: %s", service.getType(), service.getAlgorithm()));
        }

        System.out.println("provider infos : \n" + provider.getInfo());
        for (Object key : provider.keySet()) {
            System.out.println("key: " + key+ " -> value: "+provider.get(key));
        }
        KeyStore keystore = KeyStore.getInstance("PKCS11", provider);
        String alias = "ditsmeamenc";
        Scanner sc=new Scanner(System.in);
        System.out.print("ENTER THE ALIAS ??? ");
        alias=sc.nextLine();
        //char[] pin = "3C/N-7xWq-bLEF-GEq7".toCharArray();
        char[] pin = "Mb7q-X/AK-GLGA-b9sW".toCharArray();
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
            RSAPrivateKey pKey = (RSAPrivateKey) key;
            String pKeyStr = Base64.encodeBase64String(pKey.getEncoded());
            System.out.println(format("Pri Key : %s" + pKeyStr));

            Certificate cert = keystore.getCertificate(alias);
            RSAPublicKey pubKey = (RSAPublicKey) cert.getPublicKey();
            String pubKeyStr = Base64.encodeBase64String(pubKey.getEncoded());
            System.out.println(format("Pub Key : %s" + pubKeyStr));


            byte[] input = "Hello HSM !".getBytes();

            Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");

            System.out.println(format("cipher algorithm : %s", cipher.getAlgorithm()));
            System.out.println(format("algo param : %s", new String(cipher.getParameters().getEncoded())));

            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            byte[] crypted = cipher.doFinal(input);
            System.out.println(format("crypted result : %s", new String(crypted)));

            cipher.init(Cipher.DECRYPT_MODE, pKey);
            byte[] decrypted = cipher.doFinal(crypted);
            System.out.println(format("decrypted result : %s", new String(decrypted)));
        }
    }
}
