import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;

public class VerifyJWT {

    public static void main(String[] args) throws Exception {
        SignedJWT jwt = SignedJWT.parse("eyJ0eXAiOiJKV1QiLCJraWQiOiI1RzRuUmczaUpqcUJQcCtYek1MTVl0VUhvQzg9IiwiYWxnIjoiUlMyNTYifQ.eyJhdF9oYXNoIjoic0tMOEg3eUt4OHhpNU9PTXFWNTdvQSIsInN1YiI6InpyYWNoaWQiLCJhdWRpdFRyYWNraW5nSWQiOiJiYTYxZTkxZi1lMTA1LTRhYWEtODE1MC0wNjdmNjA5ZGVlZWYtMzA3NDEiLCJpc3MiOiJodHRwczovL2xvZ2luMi5hY2MuaXNhYmVsLmJlL2xvZ2luL29hdXRoMi9pc2FiZWwiLCJ0b2tlbk5hbWUiOiJpZF90b2tlbiIsIm5vbmNlIjoidGVzdDk4NyIsImF1ZCI6IkJlbGZpdXNCYW5rIiwiY19oYXNoIjoianRWOWZBVHJ2Wl9JQWNObDRlS2VjZyIsImFjciI6IjAiLCJvcmcuZm9yZ2Vyb2NrLm9wZW5pZGNvbm5lY3Qub3BzIjoiYjYwNmRiYzctMWMwMC00MjkxLWJhMGQtNTEyNzM4ZGJjZWE4IiwiYXpwIjoiQmVsZml1c0JhbmsiLCJhdXRoX3RpbWUiOjE1MjI3NTc5ODcsInJlYWxtIjoiL2lzYWJlbCIsImV4cCI6MTUyMjc1ODYwNiwidG9rZW5UeXBlIjoiSldUVG9rZW4iLCJpYXQiOjE1MjI3NTgwMDZ9.Uc5fxYXvj2TgImboio5rMWiE-7T1VxBdzPit-_b6WcWCAQWioFPE3lXRGbVnZNLFeba3A3RS7wnHbQX-vjEdFDrB8xnmHiu5WBdUXWJ02lbnSIOHRw9m1MHEXkB2nTyFObv1a_eHQ4_lJKa-GBJSNJFBBuWINJM_TQeirGume-iXrLsDzgR1kF1i7QOoJM4iHmMvOdJDameVApAwFaWigj29rdAXnU2Wjxx5q0OCrajCtEcOVWoD2I8_3XEkkofH1ocJtQfco_ajmfwU2JMfH4a-RQ1CJht91qOHcPCRksGnY0dj7fcBf_pkqL5JKSqjcos8JZ_ynkA1AUMg-LJfSQ");

        JWKSet jwkSet = JWKSet.parse("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"5G4nRg3iJjqBPp+XzMLMYtUHoC8=\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"2vAoxy7s-nX-qxMSIUbUyOTKT1Eke-U7nbhZPzFNOPNN3GS6roH09WqigCXcb8QQ3lxYzGmREXeD8kFDtb9FBKd-pcrvBhKd6E5gMdHbdya3dfJRnddQDB-EkrYlZpQQq1Ml0aJ0OYa7Ci_Lr6Hzi70y6wEhB_k0i-mbzVBArPGUZhedrV98r0Loxi3Tzbm9iRYBrKxdHxZB8CukS39MLrji4ZGN40JdIEJ3jSB54lOYTAvZF33nR4J8ZHLVEKI-Y3hylBsP0-8WJ2Qiho-Luh-lEkuHX7J2udOXvAXqT95fi0FqSeqsEMR0MoGXz8_VgPlUdes0Nkxg5mC28nAdfw\",\"e\":\"AQAB\",\"factors\":[]}]}");
        JWKSetKeyStore store = new JWKSetKeyStore(jwkSet);

        JWTSigningAndValidationService signer = new DefaultJWTSigningAndValidationService(store);

        System.out.println(signer.validateSignature(jwt));
    }

}
