# Interoperable 128-bit Aes Encryption
This is a demo using 128-bit AES encryption using CBC mode that is inter-operable in different languages.

# Languages
Java, Javascript, PHP and Python.

# Example

Encryption using Java 

  ```java
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
		} catch ( NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException e ) {
      System.out.println("Encryption exception in encrypt(): " + e);
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
		} catch ( NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException e ) {
      System.out.println("Decryption exception in decrypt(): " + e);
    } catch (Exception e) {
      System.out.println("Exception in decrypt(): " + e);
    }
    return null;
  }
  ```
  
Encryption using Node.js. Requires [crypto-js](https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.9-1/crypto-js.min.js).
  
  ```javascript
// Encryption using AES CBC (128-bits)
function encrypt(plaintext, passphrase, iv) {
  try {
    var encrypted = CryptoJS.AES.encrypt(
      plaintext,
      CryptoJS.enc.Utf8.parse(passphrase),
      { 
        mode: CryptoJS.mode.CBC, 
        iv: CryptoJS.enc.Utf8.parse(iv), 
        // PKCS#7 with 8-byte block size
        padding: CryptoJS.pad.Pkcs7 
      }
    );
    return encrypted.ciphertext.toString(CryptoJS.enc.Base64);
  } catch (error) {
    console.log('Encryption exception in encrypt(): ' + error.message);
  }
}

// Decryption using AES CBC (128-bits)
function decrypt(ciphertext, passphrase, iv) {
  try {
    var decrypted = CryptoJS.AES.decrypt(
      ciphertext,
      CryptoJS.enc.Utf8.parse(passphrase),
      { 
        mode: CryptoJS.mode.CBC, 
        iv: CryptoJS.enc.Utf8.parse(iv), 
        // PKCS#7 with 8-byte block size
        padding: CryptoJS.pad.Pkcs7 
      }
    );
    return decrypted.toString(CryptoJS.enc.Utf8);
  } catch (error) {
    console.log('Encryption exception in decrypt(): ' + error.message);
  }
}
  ```

Encryption using PHP

```php
// Encryption using AES CBC (128-bits)
function encrypt($plaintext, $passphrase, $iv) {
  try {
    $padded_str = pad_pkcs5($plaintext);
    $ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $passphrase, $padded_str, MCRYPT_MODE_CBC, $iv);
    return $ciphertext;
  } catch (Exception $e) {
    echo "Encryption exception in encrypt: " . $e->getMessage() . "\n";
  }
}

// Decrypt using AES CBC (128-bits)
function decrypt($ciphertext, $passphrase, $iv) {
  try {
		$decrypted = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $passphrase, $ciphertext, MCRYPT_MODE_CBC, $iv);
		return unpad_pkcs5($decrypted);
  } catch (Exception $e) {
    echo "Encryption exception in decrypt: " . $e->getMessage() . "\n";
  }
}
```

Encryption using Python

```python
# Encryption using AES CBC (128-bits)
def encrypt(plaintext, passphrase, iv):
  try:
    aes = AES.new(passphrase, AES.MODE_CBC, iv)
    return base64.b64encode(aes.encrypt(pad_pkcs5(plaintext)))
  except:
    print "Encryption exception in encrypt()"

# Decryption using AES CBC (128-bits)
def decrypt(ciphertext, passphrase, iv):
  try:
    decrypted = base64.b64decode(ciphertext)
    aes = AES.new(passphrase, AES.MODE_CBC, iv)
    plaintext = unpad_pkcs5(aes.decrypt(decrypted))
    return plaintext
  except:
    print "Encryption exception in decrypt()"
```

# Licence
Copyright 2017, Lamtei W

MIT Licence
