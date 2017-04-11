<?php
$KEY_SIZE = 16;
$ENCRYPTION_KEY = 'thisisasamplepassphraseforencoding';

// PKCS#5 Padding
function pad_pkcs5($text) {
  try {
    $size = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
    $pad = $size - (strlen($text) % $size);
    return $text . str_repeat(chr($pad), $pad);
  } catch (Exception $e) {
    echo "Padding exception in pad_pkcs5(): " . $e->getMessage() . "\n";
  }
}

function unpad_pkcs5($text) {
  try {
    $pad_chr = substr($text, -1);
    $pad = ord($pad_chr);

	// Check padding
    if (strspn($text, $pad_chr, strlen($text) - $pad) != $pad) 
      throw new Exception('Invalid padding');
		return substr($text, 0, -1 * $pad);
  } catch (Exception $e) {
    echo "Padding exception in unpad_pkcs5(): " . $e->getMessage() . "\n";
  }
}

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

// Driver function
function test() {
  global $ENCRYPTION_KEY, $KEY_SIZE;
  $plaintext = "Hello World!";	
	echo "Plain text: " . $plaintext . "\n";
  try {
    // Ensure that the key is no more than 16-bytes long
    $key = (strlen($ENCRYPTION_KEY) > $KEY_SIZE) ? substr($ENCRYPTION_KEY, 0, $KEY_SIZE) : $ENCRYPTION_KEY;
    $key = pack('a*', $key); // convert to binary

    // Generate initialization vector 
		$randm = mcrypt_create_iv(8, MCRYPT_DEV_URANDOM);
    $hex = bin2hex($randm);
    $iv = pack('a*', $hex); // convert to binary
    echo "IV: " . $hex . "\n";

    // Encrypt plain text
    $encrypted = encrypt($plaintext, $key, $iv);
    echo "Encrypted text: " . base64_encode($encrypted) . "\n";
		
    // Decrypt cipher text
		$decrypted = decrypt($encrypted, $key, $iv);
    echo "Decrypted text: " . $decrypted . "\n";
  } catch (Exception $e) {
    echo "An exception occurred while encrypting plain text in test(): " . $e->getMessage() . "\n";
  }
}

// Test encryption
test();
?>
