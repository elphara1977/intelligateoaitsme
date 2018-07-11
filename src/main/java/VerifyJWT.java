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
import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService;

import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;

import static java.lang.String.format;

public class VerifyJWT {

    public static final String KEYSTORE_FILE = System.getProperty("user.home") + File.separator
            + "Documents" + File.separator + "IsabelSecurityTestKeystore.jks";

    public static void main00(String[] args) throws Exception {

        Provider p = null;//new BouncyCastleProvider();
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
                    .keyID("jwtsigtest")
                    .build();

            System.out.println(jwk.toJSONString());

            System.out.println("...generated");

            JWTClaimsSet.Builder claimsSet = new JWTClaimsSet.Builder();
            claimsSet.issuer("JwtTestClient"); // mandatory
            claimsSet.subject("thisshouldbepkiofzaeher"); // mandatory
            claimsSet.audience("IntelliSign"); // mandatory
            //claimsSet.claim("givenurl", "http://maczr.local.be:8080/jwté");
            claimsSet.claim("realm", "isabel");
            URL url = new URL("http://localhost:8080/hello/Raph?" + UUID.randomUUID().toString());

            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(url.toExternalForm()), null);            //claimsSet.claim("CLIENT_URL", url.toString());
            claimsSet.jwtID(url.getPath() + ((url.getQuery() == null) ? "" : ("?" + url.getQuery())));

            Date exp = new Date(System.currentTimeMillis() + 60 * 1000); // auth good for 60 seconds
            claimsSet.expirationTime(exp); // mandatory

            Date now = new Date(System.currentTimeMillis());
            claimsSet.issueTime(now);
            claimsSet.notBeforeTime(now);

            JWSAlgorithm alg = JWSAlgorithm.RS256;
            JWKSet jwkSet = new JWKSet(jwk);

            System.out.println(format("JWKS %s", jwkSet.toJSONObject().toJSONString()));

            JWKSetKeyStore store = new JWKSetKeyStore(jwkSet);
            JWTSigningAndValidationService signer = new DefaultJWTSigningAndValidationService(store);

            JWSHeader header = new JWSHeader(alg, null, null, null, null, null, null, null, null, null,
                    signer.getDefaultSignerKeyId(),
                    null, null);

            SignedJWT jwt = new SignedJWT(header, claimsSet.build());
            signer.signJwt(jwt, alg);

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
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(ejwt.getPayload().toString()), null);
            SignedJWT signedJwt = SignedJWT.parse(ejwt.getPayload().toString());
            System.out.println("Signed JWT payload: " + signedJwt.getPayload().toString());
            System.out.println("Signed JWT claimSet: " + signedJwt.getJWTClaimsSet().toString());
            System.out.println("Original JWT claimsSet: " + jwt.getJWTClaimsSet().toString());
        }
        System.exit(0);
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

    public static void main(String[] args) throws Exception {
        SignedJWT jwt = SignedJWT.parse("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjU3MDM4M2M1LWQ5ZDgtNGI0NS05ZmY3LTE3Mjk0YmU0Mjg2YiJ9.eyJyZWFsbSI6IklzYWJlbCIsImlhdCI6MTUzMTEyODkyMywiZXhwIjoxNTMxMTMyNTIzLCJhdWQiOiJJbnRlbGxpc2lnbiIsImlzcyI6ImJlbGZpdXMiLCJzdWIiOiI1MDAyMDM3OTAwMTMxIiwianRpIjoiaHR0cHM6Ly9vcGVuYW1pZzAxLmRjNC5kZXYuaXNhbWdtdC5sb2NhbDo5NDQ0L2Zzcy9zaWduYXR1cmUvYmVsZml1cy8yMzQ2NTY4NDMzMjQwNTYwODY5MyJ9.fxDT8tme3t-kUZcfU-5p7aQrvtknBHrsv7HKu0cCkyi7TuUiJe_UDaagbJ3T2pvwCnKUuFf4uNJJojB_TYDAgbgXmHfces5p1PglMpKr35ML2lLFxkawPox4QwPtQui6vKVjYnfgrmX6rWya65bHdz6uXbgcRntzo-UqKD2u6yo59abvHgTp435PlBWM5CQr89RY5dcZEd8hQYaiW5LffkCTrGvAyM6CsauKWsycP7jHpS_ddckVG_k2MYIBKNTqjr_1PhcjJ8SA7KvOiAI_BV9k-i_Pa_hXLamx4JJU_6H5_Uyng-r8VpGcFepo12O6uxhcjNgHMMuQIqnL3vTCpA");
//        SignedJWT jwt = SignedJWT.parse("");

        //Isabel ACC JWK:
        //JWKSet jwkSet = JWKSet.parse("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"5G4nRg3iJjqBPp+XzMLMYtUHoC8=\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"2vAoxy7s-nX-qxMSIUbUyOTKT1Eke-U7nbhZPzFNOPNN3GS6roH09WqigCXcb8QQ3lxYzGmREXeD8kFDtb9FBKd-pcrvBhKd6E5gMdHbdya3dfJRnddQDB-EkrYlZpQQq1Ml0aJ0OYa7Ci_Lr6Hzi70y6wEhB_k0i-mbzVBArPGUZhedrV98r0Loxi3Tzbm9iRYBrKxdHxZB8CukS39MLrji4ZGN40JdIEJ3jSB54lOYTAvZF33nR4J8ZHLVEKI-Y3hylBsP0-8WJ2Qiho-Luh-lEkuHX7J2udOXvAXqT95fi0FqSeqsEMR0MoGXz8_VgPlUdes0Nkxg5mC28nAdfw\",\"e\":\"AQAB\",\"factors\":[]}]}");

        //Isabel DEV JWK:
        JWKSet jwkSet = JWKSet.parse("{\"keys\":[{\"kty\":\"RSA\",\"n\":\"wnL1yh91FUKzqLws7TwNcSF6NYEaYz9SWss6RmdpmnwDRAAFSBJ2wmV2_Z48wARjLKCaAipzPraWfcqC9NsJsCah58vX4eL4splG9gc1VCGU-OwEFbLXMqXXdJF0yKatyK60TzZtEpIbPuR6liWuqt07XIvhJVVA4l2n2mW0j6qmV9QKoGcK2M34rUQcu3LpceMH5uFtSW1qaswckrS06tOogjIk5NXNaZ8aprjFhrD6l9Wc1h65dJptpQBo0670k1Mg5PpTr1weQ41GqDQoaOqp43dyN29t9cbYrQ2_HQ3dO9eAgsC5M4SbAESPygkYdvV4H4zh6lItBM-WEGrIHw\",\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\"570383c5-d9d8-4b45-9ff7-17294be4286b\"}]}");
        JWKSetKeyStore store = new JWKSetKeyStore(jwkSet);

        JWTSigningAndValidationService signer = new DefaultJWTSigningAndValidationService(store);

        System.out.println(signer.validateSignature(jwt));
    }

}
