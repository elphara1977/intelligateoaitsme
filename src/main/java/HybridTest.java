import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.* ;
   
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.* ;
  
public class HybridTest {
  
    // asymmetric algorithms used
    public static String asymKeyAlgorithm = "RSA" ;
    public static String asymAlgorithm = "RSA/OAEP" ;
    public static int asymKeyAlgorithmStrength = 1024 ;
    public static String signatureAlgorithm = "SHA1WithRSAEncryption" ;
  
    // symmetric algorithms used
    public static String symKeyAlgorithm = "RIJNDAEL" ;
    public static String symAlgorithm = "RIJNDAEL" ;
    //public static String symAlgorithm = "BLOWFISH" ;
    //public static String symAlgorithm = "TWOFISH" ;
    public static int symAlgorithmStrength = 256 ;
  
    static public void main(String[] args) {
  
    String testData = "You can't have your kayak and heat it, too." ;
  
    Base64 b64 = new Base64() ;
  
    try {
        // make sure the BC provider is registered.
        Security.addProvider(new BouncyCastleProvider());
  
        SecureRandom sr = new SecureRandom() ;
  
        System.out.println("Original message byte count: " + testData.getBytes().length) ;
  
    /***
     * Generate consumer keys for test purposes.  In Real Life(TM) the
     * producer would need to know only the consumer's public key.
     ***/
        KeyPairGenerator gen = KeyPairGenerator.getInstance(asymKeyAlgorithm, "BC");
        gen.initialize(asymKeyAlgorithmStrength, sr);
 
        System.out.println("Generating key . . .") ;
        KeyPair consumerPair = gen.generateKeyPair();
  
    /***
     * on the producer side:
     * 1. Generate a secret key.
     * 2. Use asymmetric algorithm to encrypt the secret key for consumer
     * 3. Use symmetric algorithm to encrypt message using the secret key
     ***/
        // generate a random secret key
        KeyGenerator kg = KeyGenerator.getInstance(symKeyAlgorithm) ;
        kg.init(symAlgorithmStrength, sr) ;
        SecretKey cipherKey = kg.generateKey() ;
        System.out.println("Generated cipher key, proceeding: " + cipherKey.getAlgorithm()) ;
   
        // encrypt the secret key using the consumer's public key
        byte[] encryptedSecretKey = encrypt(cipherKey.getEncoded(), consumerPair.getPublic()) ;
   
        // encrypt the testData using the secret key
        byte[] encryptedData = encrypt(testData.getBytes(), cipherKey) ;
         
        System.out.println("Encrypted byte count: " + encryptedData.length) ;
        System.out.println("Encrypted message: [" + new String(b64.encode(encryptedData)) + "]") ;
  
    /***
     * uncomment to befoul the encrypted data for testing purposes
     ***/
        //encryptedData[8] = 0 ;
         
    /***
     * and now on the consumer side:
     * 1. Use asymmetric algorithm and consumer's private key to decrypt the secret key
     * 2. Use symmetric algorithm and secret key to decrypt message.
     ***/
        // first get the secret key back with the consumer's private key
        byte[] encodedSecretKey = decrypt(encryptedSecretKey, consumerPair.getPrivate()) ;
        SecretKey sKey = new SecretKeySpec(encodedSecretKey, symAlgorithm) ;
        System.out.println("Secret key decoded.") ;
  
        // decrypt the message using the secret key
        byte[] clearData = decrypt(encryptedData, sKey) ;
        System.out.println("Data decoded, byte count: " + clearData.length) ;
        System.out.println("Decrypted message: [" + new String(clearData) + "]") ;
        }
    catch ( Exception ex ) {
        ex.printStackTrace() ;
        }
         
    System.exit(0);
    }
  
    public static byte[] encrypt(byte[] toEncrypt, SecretKey key)
                    throws GeneralSecurityException {
  
    Cipher cipher = Cipher.getInstance(symAlgorithm) ;
    System.out.println("got cipher, blocksize = " + cipher.getBlockSize()) ;
    cipher.init(Cipher.ENCRYPT_MODE, key) ;
  
    byte[] result = cipher.doFinal(toEncrypt) ;
    return result ;
    }
  
    public static byte[] encrypt(byte[] toEncrypt, PublicKey key)
                    throws GeneralSecurityException {
 
    Cipher cipher = Cipher.getInstance(asymAlgorithm) ;
    cipher.init(Cipher.ENCRYPT_MODE, key) ;
  
    byte[] result = cipher.doFinal(toEncrypt) ;
    return result ;
    }
  
    public static byte[] decrypt(byte[] toDecrypt, SecretKey key)
                    throws GeneralSecurityException {
  
    Cipher deCipher = Cipher.getInstance(symAlgorithm) ;
    deCipher.init(Cipher.DECRYPT_MODE, key) ;
  
    byte[] result = deCipher.doFinal(toDecrypt) ;
    return result ;
    }
  
    public static byte[] decrypt(byte[] toDecrypt, PrivateKey key)
                    throws GeneralSecurityException {
  
    Cipher deCipher = Cipher.getInstance(asymAlgorithm) ;
    deCipher.init(Cipher.DECRYPT_MODE, key) ;
  
    byte[] result = deCipher.doFinal(toDecrypt) ;
    return result ;
    }
    }