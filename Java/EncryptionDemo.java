import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class EncryptionDemo {

  private static int KEY_SIZE = 16;
  private static String ENCRYPTION_KEY = "thisisasamplepassphraseforencoding";

  public static void main(String[] args) {
    String plaintext = "Hello World!";
    System.out.println("Plain text: " + plaintext);
    try {
      // Ensure that the key is no more than 16-bytes long
      String passphrase = (ENCRYPTION_KEY.length() > KEY_SIZE) ? ENCRYPTION_KEY.substring(0, KEY_SIZE) : ENCRYPTION_KEY;
      byte[] key = passphrase.getBytes("UTF-8");

      // Generate initialization vector 
      byte[] iv = generateInitializationVector(KEY_SIZE);
      System.out.println("IV: " + new String(iv, "UTF-8"));
      
      // Encrypt plain text
      String ciphertext = encrypt(plaintext.getBytes("UTF-8"), key, iv);
      System.out.println("Encrypted text: " + ciphertext);
      
      // Decrypt cipher text
      String decryptedtext = decrypt(ciphertext, key, iv);
      System.out.println("Decrypted text: " + decryptedtext);
    } catch (Exception e) {
      System.out.println("An exception occurred while encrypting plain text in main(): " + e);
    }
  }

  /**
   * Encrypt using AES 128-bit encryption with CBC mode
   * 
   * @param plaintext (byte[]) The plain text
   * @param key (byte[]) The secret key
   * @param iv (byte) the initializatoin vector
   *
   * @return (String) Encrypted text
   */
  private static String encrypt(byte[] plaintext, byte[] key, byte[] iv) {
    try {
      SecretKeySpec secretKeySpec;
      secretKeySpec = new SecretKeySpec(key, "AES");
      
      // PKCS#5 Padding
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      AlgorithmParameters algorithmParams = AlgorithmParameters.getInstance("AES");
      algorithmParams.init(new IvParameterSpec(iv));
      cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, algorithmParams);
      byte[] encryptedBytes = cipher.doFinal(plaintext);
      return DatatypeConverter.printBase64Binary(encryptedBytes);
    } catch (NoSuchPaddingException | BadPaddingException e) {
      System.out.println("Padding exception in encrypt(): " + e);
    } catch ( NoSuchAlgorithmException | InvalidKeyException	| IllegalBlockSizeException e ) {
      System.out.println("Validation exception in encrypt(): " + e);
    } catch (Exception e) {
      System.out.println("Exception in encrypt(): " + e);
    }
    return null;
  }
  
  /**
   * Decrypt using AES 128-bit encryption with CBC mode
   * 
   * @param ciphertext (byte[]) The cipher text
   * @param key (byte[]) The secret key
   * @param iv (byte) the initializatoin vector
   *
   * @return (String) Plain text
   */
  public static String decrypt(String ciphertext, byte[] key, byte[] iv ) {
    try {
      SecretKeySpec secretKeySpec;
      secretKeySpec = new SecretKeySpec(key, "AES");
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      AlgorithmParameters algorithmParams = AlgorithmParameters.getInstance("AES");
      algorithmParams.init(new IvParameterSpec(iv));
      cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, algorithmParams);
      return new String(cipher.doFinal(DatatypeConverter.parseBase64Binary(ciphertext)), "UTF-8");
    } catch (NoSuchPaddingException | BadPaddingException e) {
      System.out.println("Padding exception in decrypt(): " + e);
    } catch ( NoSuchAlgorithmException | InvalidKeyException	| IllegalBlockSizeException e ) {
      System.out.println("Validation exception in decrypt(): " + e);
    } catch (Exception e) {
      System.out.println("Exception in decrypt(): " + e);
    }
    return null;
  }
  

  /**
   * Utility function to generate initialization vector
   *
   * @return bytes
   */
  private static byte[] generateInitializationVector(int len) {
    try {
      char[] CHAR_ARRAY = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456879".toCharArray();
      SecureRandom srand = new SecureRandom();
      Random rand = new Random();
      StringBuilder sb = new StringBuilder();
      for (int i = 0; i < len; ++i) {
        if ((i % 10) == 0) {
          rand.setSeed(srand.nextLong());
        }
        sb.append(Integer.toHexString(rand.nextInt(CHAR_ARRAY.length)));
      }
      return sb.toString().substring(0, KEY_SIZE).getBytes("UTF-8");
    } catch (Exception e) {
      System.out.println("Error generating Initialization Vector: " + e);
    }
    return null; 
  }
}
