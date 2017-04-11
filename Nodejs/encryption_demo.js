var CryptoJS = require("crypto-js");
 
var KEY_SIZE = 16;
var ENCRYPTION_KEY = "thisisasamplepassphraseforencoding";

try {
  var plaintext = 'Hello World!';
  console.log("Plain text: " + plaintext);
	
  // Ensure that the key is no more than 16-bytes long
  var key = (ENCRYPTION_KEY.length > KEY_SIZE ) ? ENCRYPTION_KEY.substr(0, KEY_SIZE) : ENCRYPTION_KEY;
	
  // Generate pseudo string for IV 
  var iv = CryptoJS.lib.WordArray.random(8).toString();
  console.log('IV: ' + iv);

  // Encrypt plain text
  var encrypted = encrypt(plaintext, key, iv);
  console.log('Encrypted text: ' + encrypted);
	
  // Decrypt cipher text
  var decrypted = decrypt(encrypted, key, iv);
  console.log('Decrypted text: ' + decrypted);
	
} catch (error) {
  console.log('An exception occurred while encrypting plain text: ' + error.message);
}

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
