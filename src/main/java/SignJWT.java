import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService;

import java.io.File;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

import static java.lang.String.format;

public class SignJWT {

    public static final String KEYSTORE_FILE = System.getProperty("user.home") + File.separator
            + "Documents" + File.separator + "IsabelSecurityTestKeystore.jks";

    public static void main0(String[] args) throws ParseException, InvalidKeySpecException, NoSuchAlgorithmException {
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

        s="{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"kz9THWHmGU0yw8wZPzyIv5JV4Zo=\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"xEvGoFEDWCnBr99ZG_LWTElxnu1JNHC1U1-lu9aM6gBZOYeVXFl1Cf-EB9VtXPJYxgR9UPuGe2yWuWPnfi1LxHXsecYSi7oQ2XdjJzueys7mZubiNijAvALPXANoq70Cw-05_pcgvOb5HrxB3Opprz7cON1P_3eAiwi1RLqEdPmNKgfZu841vuv4PHTZONSHqH-nnLRvxVKRlB63OLvrxdmhIMK3b-fJQGr_CT_6827NnVmbe_8KyVhbba-uFRi6jEc8RSZnk5mHpJoiFNeJprgKUyklDGEyTkDqG5d6_uta4UC_WriE085f9e8hRPVGxESa7rBYVeYI4yDaSqAAXQ\",\"e\":\"AQAB\",\"factors\":[]}]}";

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
    }

    public static void main(String[] args) throws Exception {

        Provider p = new BouncyCastleProvider();
        Security.addProvider(p);

        System.out.println("generating jwkSet...");
        // Generate the RSA key pair
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(Files.newInputStream(Paths.get(KEYSTORE_FILE)), "password".toCharArray());

        final String alias = "jwt";
        Key key = ks.getKey(alias, "password".toCharArray());
        if (key instanceof PrivateKey) {
            // Get certificate of public key
            Certificate cert = ks.getCertificate(alias);
            // Get public key
            PublicKey publicKey = cert.getPublicKey();

            // Convert to JWK format
            JWK jwk = new RSAKey.Builder((RSAPublicKey) publicKey)
                    .privateKey((RSAPrivateKey) key)
                    .keyID(UUID.randomUUID().toString()) // Give the key some ID (optional)
                    .keyID("rsa1")
                    .build();

            System.out.println(jwk.toJSONString());

            System.out.println("...generated");

            JWTClaimsSet.Builder claimsSet = new JWTClaimsSet.Builder();
            claimsSet.issuer("simplewebapp"); // mandatory
            //claimsSet.subject("500012345679"); // mandatory
            claimsSet.audience("Intellisign"); // mandatory
            //claimsSet.claim("givenurl", "http://maczr.local.be:8080/jwté");
            claimsSet.claim("realm", "isabel");
            claimsSet.claim("CLIENT_URL", "http://www.test.com");
            claimsSet.jwtID(UUID.randomUUID().toString());

            Date exp = new Date(System.currentTimeMillis() + 60 * 1000); // auth good for 60 seconds
            claimsSet.expirationTime(exp); // mandatory

            Date now = new Date(System.currentTimeMillis());
            claimsSet.issueTime(now);
            claimsSet.notBeforeTime(now);

            JWSAlgorithm alg = JWSAlgorithm.RS256;
            JWKSet jwkSet=new JWKSet(jwk);

            System.out.println(format("JWKS %s",jwkSet.toJSONObject().toJSONString()));

            //JWKSetKeyStore store = new JWKSetKeyStore(jwkSet);
            //JWTSigningAndValidationService signer = new DefaultJWTSigningAndValidationService(store);
            //JWKSet jwkS = JWKSet.load(new URL("https://am1.rockkit.org:8443/login/oauth2/realms/root/realms/isabel/connect/jwk_uri"));
            JWKSet jwkS = JWKSet.parse("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"kz9THWHmGU0yw8wZPzyIv5JV4Zo=\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"xEvGoFEDWCnBr99ZG_LWTElxnu1JNHC1U1-lu9aM6gBZOYeVXFl1Cf-EB9VtXPJYxgR9UPuGe2yWuWPnfi1LxHXsecYSi7oQ2XdjJzueys7mZubiNijAvALPXANoq70Cw-05_pcgvOb5HrxB3Opprz7cON1P_3eAiwi1RLqEdPmNKgfZu841vuv4PHTZONSHqH-nnLRvxVKRlB63OLvrxdmhIMK3b-fJQGr_CT_6827NnVmbe_8KyVhbba-uFRi6jEc8RSZnk5mHpJoiFNeJprgKUyklDGEyTkDqG5d6_uta4UC_WriE085f9e8hRPVGxESa7rBYVeYI4yDaSqAAXQ\",\"e\":\"AQAB\",\"factors\":[]}]}");
            JWKSetKeyStore store=new JWKSetKeyStore(jwkS);
            JWTSigningAndValidationService signer = new DefaultJWTSigningAndValidationService(store);

            JWSHeader header = new JWSHeader(alg, null, null, null, null, null, null, null, null, null,
                    signer.getDefaultSignerKeyId(),
                    null, null);

            SignedJWT jwt = new SignedJWT(header, claimsSet.build());
            signer.signJwt(jwt);

            // Create JWE object with signed JWT as payload
            JWEObject jweObject = new JWEObject(
                    new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256)
                            .contentType("JWT").keyID(getKid("enc", alias, publicKey)) // required to signal nested JWT
                            .build(),
                    new Payload(jwt));


            // Create an encrypter with the specified public RSA key
            RSAEncrypter encrypter = new RSAEncrypter((RSAPublicKey) publicKey);
            encrypter.getJCAContext().setProvider(p);

            //System.out.println(format("JWEObj: %s",jweObject.getEncryptedKey()));

            // Perform encryption
            jweObject.encrypt(encrypter);

            // Serialise to JWE compact form
            String jweStr = jweObject.serialize();

            System.out.println("Encrypted: " + jweStr);
            // Parse back
            EncryptedJWT ejwt = EncryptedJWT.parse(jweStr);

            // Create a decrypter with the specified private RSA key
            RSADecrypter decrypter = new RSADecrypter((PrivateKey) key);
            decrypter.getJCAContext().setProvider(p);

            // Decrypt
            ejwt.decrypt(decrypter);

            System.out.println("Decrypted: " + ejwt.getPayload());
            SignedJWT signedJwt = SignedJWT.parse(ejwt.getPayload().toString());
            System.out.println("Signed JWT payload: "+signedJwt.getPayload().toString());
            System.out.println("Signed JWT claimSet: "+signedJwt.getJWTClaimsSet().toString());
            System.out.println("Original JWT claimsSet: " + jwt.getJWTClaimsSet().toString());
        }

    }

    public static String getKid(String keyUse, String alias, PublicKey key) {
        if (key instanceof RSAPublicKey) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) key;
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

    public static String hash(String input) {
        return hash("SHA-1", input);
    }

}
