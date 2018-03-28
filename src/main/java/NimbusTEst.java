import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;

public class NimbusTEst {

    public static void main(String[] args) {
        // To encrypt
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM);
        Payload payload = new Payload("Hello world!");

        JWEObject jweObject = new JWEObject(header, payload);

        JWEEncrypter encrypter = new RSAEncrypter(publicKey);
        encrypter.setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

        jweObject.encrypt(encrypter);

        String jweString = jweObject.serialize();

// To decrypt
        jweObject = JWEObject.parse(jweString);

        JWEDecrypter decrypter = new RSADecrypter(privateKey);
        decrypter.setKeyEncryptionProvider(BouncyCastleProviderSingleton.getInstance());

        jweObject.decrypt(decrypter);

        System.out.println(jweObject.getPayload());
    }

}
