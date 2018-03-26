import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.binary.Base64;
import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService;
import sun.security.pkcs11.SunPKCS11;

import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;

public class SignTestJwtOriginal {


    public static void main(String[] args ) {
        JWEAlgorithm algo = null;
        EncryptionMethod encMeth = null;
        String alias = null;
        String password = null;
        if (args.length >=2) {
            if (args[0] != null) algo = JWEAlgorithm.parse(args[0]);
            if (args[1] != null) encMeth = EncryptionMethod.parse(args[1]);
        }
        if (args.length>=4) {
            if (args[2] != null) alias = args[2];
            if (args[3] != null) password = args[3];
        }
        sign(algo, encMeth, alias, password);
    }

    public static void sign(JWEAlgorithm algo, EncryptionMethod encMeth, String aliass, String passw){
        try {
            RSAPublicKey  publicKey = null;

            Key key = null;

            Provider p = null;

            try {


                FileInputStream is = new FileInputStream("/Users/zrachid/NetbeansProjects/rockkit/sampleprojectssl/deploy/src/main/config/VAGRANT/vagrant/ansible/roles/openam-security-files/files/openam_login_keystore.jceks");
                KeyStore keystore = KeyStore.getInstance("JCEKS");

                String password = "changeit";
                char[] passwd = password.toCharArray();
                keystore.load(is, passwd);
                String alias = "openam";
                p = keystore.getProvider();

                //String configName = "/opt/forgerock/software/softhsm/pkcs11.conf";
                /*String configName = "/usr/safenet/luna.cfg";


                p = new SunPKCS11(configName);
                */
                for (Provider.Service service: p.getServices()) {
                    System.out.println(service.getType() + " : " + service.getAlgorithm());
                }

                /*
                if (-1 == Security.addProvider(p)) {
                    throw new RuntimeException("could not add security provider");
                }
                String alias = "authsigner";
                if (aliass != null) alias= aliass;
                String password = "123456";
                if (passw != null) password = passw;
                char[] passwd = password.toCharArray();

                // Load the key store
                char[] pin = password.toCharArray();
                KeyStore keystore = KeyStore.getInstance("PKCS11", p);
                keystore.load(null, pin);

                */

                key = keystore.getKey(alias, passwd);
                if (key instanceof PrivateKey) {
                    Certificate cert = keystore.getCertificate(alias);
                    // Get public key
                    publicKey = (RSAPublicKey) cert.getPublicKey();

                    String publicKeyString = Base64.encodeBase64String(publicKey
                            .getEncoded());
                    System.out.println(publicKeyString);

                }

            } catch (Exception e) {
                e.printStackTrace();
            }
            String s = "{\n" +
                    "  \"keys\": [\n" +
                    "    {\n" +
                    "      \"alg\": \"RSA256\",\n" +
                    "      \"d\": \"GIW2b3-ig8rk-Pm3cD5VqRSxtKBJfNhuBCSNe1N6-_kGrk3M5MWgqEbJCzdoZz8M8fclE8sV11b9_-iQx2iVjaw77gHsGe-IUucSNEeW2VtvbpvgCklw-B3CathBMOuHzqCbafj-J6zJ9uxGUFhgUKkLWZJ1iSuIw7WfKoBx_jU\",\n" +
                    "      \"e\": \"AQAB\",\n" +
                    "      \"n\": \"qYJqXTXsDroPYyQBBmSolK3bJtrSerEm-nrmbSpfn8Rz3y3oXLydvUqj8869PkcEzoJIY5Xf7xDN1Co_qyT9qge-3C6DEwGVHXOwRoXRGQ_h50Vsh60MB5MIuDN188EeZnQ30dtCTBB9KDTSEA2DunplhwLCq4xphnMNUaeHdEk\",\n" +
                    "      \"kty\": \"RSA\",\n" +
                    "      \"kid\": \"rsa1\"\n" +
                    "    }\n" +
                    "  ]\n" +
                    "}";

            //System.out.println("all keys:"+s);

            JWKSet jwkSet = JWKSet.parse(s);
            JWKSetKeyStore store = new JWKSetKeyStore(jwkSet);

            JWTSigningAndValidationService signer = new DefaultJWTSigningAndValidationService(store);



            JWTClaimsSet.Builder claimsSet = new JWTClaimsSet.Builder();

            claimsSet.issuer("simplewebapp"); // mandatory
            claimsSet.subject("500012345679"); // mandatory
            //claimsSet.audience("https://am1.rockkit.org:8443/login/oauth2/realms/root/realms/isabel/access_token"); // mandatory
            claimsSet.audience("Intellisgn"); // mandatory
            claimsSet.claim("givenurl", "http://maczr.local.be:8080/jwté");
            claimsSet.claim("realm", "isabel");
            claimsSet.claim("test", "test");
            claimsSet.jwtID(UUID.randomUUID().toString());

            // TODO: make this configurable
            Date exp = new Date(System.currentTimeMillis() + (300 * 1000)); // auth good for 60 seconds
            claimsSet.expirationTime(exp); // mandatory

            Date now = new Date(System.currentTimeMillis());
            claimsSet.issueTime(now);
            claimsSet.notBeforeTime(now);

            JWSAlgorithm alg = JWSAlgorithm.RS256;

            JWSHeader header = new JWSHeader(alg, null, null, null, null, null, null, null, null, null,
                    signer.getDefaultSignerKeyId(),
                    null, null);
            SignedJWT jwt = new SignedJWT(header, claimsSet.build());

            signer.signJwt(jwt, alg);

            if (algo == null) algo = JWEAlgorithm.RSA_OAEP;
            if (encMeth == null) encMeth = EncryptionMethod.A128CBC_HS256;
            System.out.println("Encryption tested using algo:"+algo+" encMeth:"+encMeth);

            // Create JWE object with signed JWT as payload
            JWEObject jweObject = new JWEObject(
                    new JWEHeader.Builder(algo,encMeth)
                            .contentType("JWT").keyID(getKid("enc","openam",publicKey)) // required to signal nested JWT
                            .build(),
                    new Payload(jwt));
            // Create an encrypter with the specified public RSA key
            RSAEncrypter encrypter = new RSAEncrypter(publicKey);
            encrypter.getJCAContext().setProvider(p);

// Perform encryption
            jweObject.encrypt(encrypter);

// Serialise to JWE compact form
            String jweString = jweObject.serialize();

            System.out.println("Encrypted: "+jweString);
// Parse back
            EncryptedJWT ejwt = EncryptedJWT.parse(jweString);

// Create a decrypter with the specified private RSA key
            RSADecrypter decrypter = new RSADecrypter((PrivateKey) key);
            decrypter.getJCAContext().setProvider(p);

// Decrypt
            ejwt.decrypt(decrypter);

            System.out.println("Decrypted: "+ejwt.getPayload().toString());

            SignedJWT fSignedJwt = SignedJWT.parse(ejwt.getPayload().toString());
            System.out.println("Signed JWT payloed: "+fSignedJwt.getPayload().toString());
            System.out.println("Signed JWT claimSet: "+fSignedJwt.getJWTClaimsSet().toString());

            System.out.println("client_assertion_type:urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            System.out.println("client_assertion:" + jwt.getJWTClaimsSet().toString());
        } catch (Exception s) {
            s.printStackTrace();
        }

    }

    public static String getKid(String keyUse, String alias, PublicKey key) {
        if (key instanceof RSAPublicKey) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey)key;
            return hash(alias + ":" + keyUse + rsaPublicKey.getModulus().toString() + rsaPublicKey.getPublicExponent().toString());
        } else {
            throw new IllegalArgumentException("Public key type '" + key + "' not supported.");
        }
    }

    public static String hash(String algorithm, String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            digest.update(input.getBytes(StandardCharsets.UTF_8));
            return Base64.encodeBase64String(digest.digest());
        } catch (NoSuchAlgorithmException var3) {
            var3.printStackTrace();
            return null;
        }
    }

    /** @deprecated */
    @Deprecated
    public static String hash(String input) {
        return hash("SHA-1", input);
    }
}
