import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.safenetinc.luna.provider.LunaProvider;
import sun.security.pkcs11.SunPKCS11;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.UUID;

import static java.lang.String.format;

public class NimbusTest {

    public static void main(String[] args) throws Exception {

        Security.addProvider(new LunaProvider());

        // Set up the Sun PKCS 11 provider
        //String configName = "/opt/forgerock/software/softhsm/softhsm.conf";
        String configName = "/opt/forgerock/software/softhsm/pkcs11.conf";
        Provider p = new SunPKCS11(configName);

        char[] pin = "123456".toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS11", p);
        keyStore.load(null, pin);

        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            System.out.println("alias " + aliases.nextElement());
        }

        PrivateKey pkey = (PrivateKey) keyStore.getKey("authsigner", "123456".toCharArray());
        PublicKey key = keyStore.getCertificate("authsigner").getPublicKey();

        System.out.println("key : " + key.getAlgorithm() + " " + key.getClass());

        if (key instanceof RSAPublicKey) {
            RSAPublicKey pubkey = (RSAPublicKey) key;

            // Compose the JWT claims set
            Date now = new Date();

            JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                    .issuer("https://openid.net")
                    .subject("alice")
                    .audience(Arrays.asList("https://app-one.com", "https://app-two.com"))
                    .expirationTime(new Date(now.getTime() + 1000 * 60 * 10)) // expires in 10 minutes
                    .notBeforeTime(now)
                    .issueTime(now)
                    .jwtID(UUID.randomUUID().toString())
                    .build();

            System.out.println(jwtClaims.toJSONObject());


// Produces
// {
//   "iss" : "https:\/\/openid.net",
//   "sub" : "alice",
//   "aud" : [ "https:\/\/app-one.com" , "https:\/\/app-two.com" ],
//   "exp" : 1364293137871,
//   "nbf" : 1364292537871,
//   "iat" : 1364292537871,
//   "jti" : "165a7bab-de06-4695-a2dd-9d8d6b40e443"
// }

// Request JWT encrypted with RSA-OAEP-256 and 128-bit AES/GCM
            JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256);

// Create the encrypted JWT object
            EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);

// Create an encrypter with the specified public RSA key
            RSAEncrypter encrypter = new RSAEncrypter(pubkey);
            encrypter.getJCAContext().setProvider(p);

// Do the actual encryption
            jwt.encrypt(encrypter);

// Serialise to JWT compact form
            String jwtString = jwt.serialize();

            System.out.println(jwtString);


// Produces
//
// eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ.K52jFwAQJH-
// DxMhtaq7sg5tMuot_mT5dm1DR_01wj6ZUQQhJFO02vPI44W5nDjC5C_v4p
// W1UiJa3cwb5y2Rd9kSvb0ZxAqGX9c4Z4zouRU57729ML3V05UArUhck9Zv
// ssfkDW1VclingL8LfagRUs2z95UkwhiZyaKpmrgqpKX8azQFGNLBvEjXnx
// -xoDFZIYwHOno290HOpig3aUsDxhsioweiXbeLXxLeRsivaLwUWRUZfHRC
// _HGAo8KSF4gQZmeJtRgai5mz6qgbVkg7jPQyZFtM5_ul0UKHE2y0AtWm8I
// zDE_rbAV14OCRZJ6n38X5urVFFE5sdphdGsNlA.gjI_RIFWZXJwaO9R.oa
// E5a-z0N1MW9FBkhKeKeFa5e7hxVXOuANZsNmBYYT8G_xlXkMD0nz4fIaGt
// uWd3t9Xp-kufvvfD-xOnAs2SBX_Y1kYGPto4mibBjIrXQEjDsKyKwndxzr
// utN9csmFwqWhx1sLHMpJkgsnfLTi9yWBPKH5Krx23IhoDGoSfqOquuhxn0
// y0WkuqH1R3z-fluUs6sxx9qx6NFVS1NRQ-LVn9sWT5yx8m9AQ_ng8MBWz2
// BfBTV0tjliV74ogNDikNXTAkD9rsWFV0IX4IpA.sOLijuVySaKI-FYUaBy
// wpg

// Parse back
            jwt = EncryptedJWT.parse(jwtString);

// Create a decrypter with the specified private RSA key
            PrivateKey privateKey = null;
            RSADecrypter decrypter = new RSADecrypter(pkey);
            decrypter.getJCAContext().setProvider(p);
// Decrypt
            jwt.decrypt(decrypter);

// Retrieve JWT claims
            System.out.println(jwt.getJWTClaimsSet().getIssuer());
            ;
            System.out.println(jwt.getJWTClaimsSet().getSubject());
            System.out.println(jwt.getJWTClaimsSet().getAudience().size());
            System.out.println(jwt.getJWTClaimsSet().getExpirationTime());
            System.out.println(jwt.getJWTClaimsSet().getNotBeforeTime());
            System.out.println(jwt.getJWTClaimsSet().getIssueTime());
            System.out.println(jwt.getJWTClaimsSet().getJWTID());
        }

    }

}
