import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService;

import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

public class GenerateJWT {

    private static final String KEYSTORE_FILE = System.getProperty("user.home") + File.separator
            + "Documents" + File.separator + "IsabelSecurityTestKeystore.jks";

    public static void main(String[] args) throws Exception {

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

            System.out.println(jwk.toPublicJWK().toJSONString());

            JWTClaimsSet.Builder claimsSet = new JWTClaimsSet.Builder();
            claimsSet.issuer("JwtTestClient"); // mandatory
            claimsSet.subject("thisshouldbepkiofzaeher"); // mandatory
            claimsSet.audience("IntelliSign"); // mandatory
            claimsSet.claim("realm", "isabel");
            URL url = new URL("http://localhost:8080/hello/Raph?" + UUID.randomUUID().toString());
            System.out.println(url);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(url.toExternalForm()), null);
            claimsSet.jwtID(url.getPath() + ((url.getQuery() == null) ? "" : ("?" + url.getQuery())));

            Date exp = new Date(System.currentTimeMillis() + 60 * 1000); // auth good for 60 seconds
            claimsSet.expirationTime(exp); // mandatory

            Date now = new Date(System.currentTimeMillis());
            claimsSet.issueTime(now);
            claimsSet.notBeforeTime(now);

            JWSAlgorithm alg = JWSAlgorithm.RS256;
            JWKSet jwkSet = new JWKSet(jwk);

            JWKSetKeyStore store = new JWKSetKeyStore(jwkSet);
            JWTSigningAndValidationService signer = new DefaultJWTSigningAndValidationService(store);

            JWSHeader header = new JWSHeader(alg, null, null, null, null, null, null, null, null, null,
                    signer.getDefaultSignerKeyId(),
                    null, null);

            SignedJWT jwt = new SignedJWT(header, claimsSet.build());
            signer.signJwt(jwt, alg);

            final String jwtStr = jwt.serialize();
            TimeUnit.MILLISECONDS.sleep(500L);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(jwtStr), null);
            Toolkit.getDefaultToolkit().beep();
            System.out.println("JWT: " + jwtStr);
        }
        System.exit(0);
    }
};