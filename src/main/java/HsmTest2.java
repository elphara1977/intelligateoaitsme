import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.security.pkcs11.SunPKCS11;

import javax.crypto.Cipher;
import javax.xml.crypto.AlgorithmMethod;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import static java.lang.String.format;

public class HsmTest2 {

    public static void main(String[] args) throws Exception {
        //String configName = "/usr/safenet/luna.cfg";
        String configName = "./opt/forgerock/software/softhsm/softhsm.conf";

//        Provider provider = new SunPKCS11(configName);

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        for (Provider.Service service : provider.getServices()) {

            String serviceStr = format("Service Type : %s  ---  Algorithm: %s", service.getType(), service.getAlgorithm());
            if (serviceStr.toLowerCase().contains("oaep"))
                System.out.println(serviceStr);
        }

//        KeyStore keystore = KeyStore.getInstance("PKCS11", provider);
//        String alias = "ditsmeamenc";
//        char[] pin = "3C/N-7xWq-bLEF-GEq7".toCharArray();
//        keystore.load(null, pin);
//
//        Key key = keystore.getKey(alias, pin);
//        System.out.println("key format : " + key.getFormat());
//        System.out.println("key class : " + key.getClass());

        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(2048, random);
        KeyPair pair = generator.generateKeyPair();
        RSAPublicKey pubKey = (RSAPublicKey) pair.getPublic();
        RSAPrivateKey pKey = (RSAPrivateKey) pair.getPrivate();

//        RSAPrivateKey pKey = (RSAPrivateKey) key;
        String pKeyStr = Base64.encodeBase64String(pKey.getEncoded());
        System.out.println(format("Pri Key : %s", pKeyStr));

//        Certificate cert = keystore.getCertificate(alias);
//        RSAPublicKey pubKey = (RSAPublicKey) cert.getPublicKey();
        String pubKeyStr = Base64.encodeBase64String(pubKey.getEncoded());
        System.out.println(format("Pub Key : %s", pubKeyStr));


        byte[] input = "Hello HSM !".getBytes();
        System.out.println(format("clear text : ", new String(input)));

//        Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
        Cipher cipher = Cipher.getInstance("RSA/OAEP");

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
