/**
 * Copyright 2013 Chris Wood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.ceperman.textcrypt;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;

import org.mindrot.jbcrypt.BCrypt;

/**
 * Encryption overview
 * 
 * Uses bcrypt, which is a key derivation function for passwords designed by Niels Provos and David Mazi\\u00E8res and based
 * on the Blowfish cipher. It implements "key stretching" whereby a random salt is incorporated into the user-provided
 * password to make the encryption key more complex in order to be more resistant to dictionary attacks. It is also
 * notable for its expensive key setup phase which is an adaptive algorithm: over time, the iteration count can be
 * increased to make it slower, so it remains resistant to brute-force search attacks even with increasing computation
 * power.
 * 
 * (The terms "bcrypt" and "key stretching" are described in detail in Wikipedia.)
 * 
 * The password provided by the user is used to create a cipher (encryption/decryption algorithm) that encrypts the
 * data. A random string (the "salt") is added to the user-provided password to make it more complex, and an iterative
 * hash of this created to form the key. The password hash is used by the cipher as the key. The process is symmetrical,
 * so the same salt and iteration count must be provided for decryption.
 * 
 * The implementation uses blowfish encryption. Encryption/decryption is implemented by the blowfish provider jar. The
 * key hashing mechanism is provided by bcrypt.
 * 
 * @author Chris Wood
 */
public class CryptUtils {
   private static Logger logger = Logger.getLogger(CryptUtils.class.getName());

   /* Blowfish AES encryption with SHA key */
   private static final String KEY_FACTORY = "PBEWITHSHA-256AND256BITAES-CBC-BC";
   private static final int defaultKeyLength = 128;

   /** Return value of createCiphers function. */
   static class CipherInfo { /* package access */
      Cipher encryptCipher;
      Cipher decryptCipher;
      byte[] salt;
      int rounds;
   }

   /** Return value for the getSaltAndRounds() function. */
   static class SaltAndRounds { /* package access */
      byte[] salt;
      int rounds;

      SaltAndRounds(byte[] salt, int rounds) {
         this.salt = salt;
         this.rounds = rounds;
      }
   }

   /**
    * Creates a new unique random salt.
    * 
    * @return A new salt value used to generate the secret key.
    */
   private static byte[] createNewSalt() {
      byte[] bytes = new byte[BCrypt.BCRYPT_SALT_LEN];
      SecureRandom random = new SecureRandom();
      random.nextBytes(bytes);
      return bytes;
   }

   /**
    * Add the BouncyCastle JCE provider if not already available
    */
   public static void checkBCProvider() {
      if (Security.getProvider("BC") == null) {
         logger.log(Level.FINE, "Adding BouncyCastle JCE provider");
         Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
         logger.log(Level.FINE, "Added BouncyCastle JCE provider successfully");
      }
   }

   /**
    * Determines the ideal number of rounds to use for the bcrypt algorithm. More rounds are more secure, but require
    * more time to generate. This function tries to balance security and convenience.
    * 
    * Each round increment doubles the amount of work required by bcrypt to generate a key. This function assumes that
    * time is proportional to work. So for example, if 4 rounds takes 0.1 seconds to generate a key, 5 rounds will take
    * 0.2 seconds, 6 rounds 0.4 seconds, and so on. The assumption will be that the key must be generated in less than
    * 0.9 seconds to remain convenient for the user.
    * 
    * This function calculate how long it takes to generate a key using 4 rounds on the current device, then estimates
    * the maximum number of rounds such that the time to generate will remain below the convenience threshold.
    * 
    * @return number of rounds
    */
   public static int determineBestRounds() {
      byte[] salt = createNewSalt();
      int plaintext[] = { 0x155cbf8e, 0x57f57513, 0x3da787b9, 0x71679d82, 0x7cf72e93, 0x1ae25274, 0x64b54adc,
            0x335cbd0b };
      final byte[] password = { 1, 2, 3, 4, 5, 6, 7, 8 };
      BCrypt bcrypt = new BCrypt();

      /*
       * Define number of test rounds here. Choose a value such that the interval is significantly greater than the
       * clock resolution, but also significantly less than the target overall digest time (900ms). Around 20-50 ms is
       * ideal.
       */
      int testrounds = 6;

      // Calculate the time to create a cipher key with the specified rounds, in
      // msecs.
      // Do it a number of times and take the average.
      final long start = System.currentTimeMillis();
      bcrypt.crypt_raw(password, salt, testrounds, plaintext);
      bcrypt.crypt_raw(password, salt, testrounds, plaintext);
      final long Ttestrounds = (System.currentTimeMillis() - start) / 2;

      // If Tm is the time in msecs to create the key with m rounds, then
      // the time Tn to calculate the key using n rounds (n > m) is:
      //
      // Tn = 2^(n - m) * Tm
      //
      // where we want Tn to be less than e.g. 900 msecs. Solving for n gives:
      //
      // Tn = 2^(n - m) * Tm < 900
      // n - m + log2(Tm) < log2(900)
      // n < m + log2(900) - log2(Tm) -- solve for n
      // n < m + ln(900)/ln(2) - ln(Tm)/ln(2) -- convert to natural logs
      //
      // The best number of rounds is the floor of n.
      int MAX_TIME = 900;
      final double n = testrounds + (Math.log(MAX_TIME) - Math.log(Ttestrounds)) / Math.log(2);
      int rounds = (int) n;

      logger.log(Level.FINE, "determineBestRounds: time for " + testrounds + " rounds - " + Ttestrounds
                  + " ms, calculated rounds - " + rounds);
      // Make sure rounds does not exceed its valid range.
      if (rounds < 4) {
         rounds = 4;
      } else if (rounds > 31) {
         rounds = 31;
      }

      return rounds;
   }

   /**
    * Create a pair of encryption and decryption ciphers based on the given password string. The string is not stored
    * internally. This function needs to be called before calling getEncryptionCipher() or getDecryptionCipher().
    * 
    * @param password
    *           String to use for creating the ciphers.
    * @param salt
    *           The salt to use when creating the encryption key.
    * @param rounds
    *           The number of rounds for bcrypt.
    * @param keylength
    * @return CipherInfo structure with information about the created ciphers.
    */
   public static CipherInfo createCiphers(byte[] password, byte[] salt, int rounds, int keylength) {
      CipherInfo info = new CipherInfo();
      final long start = System.currentTimeMillis();

      byte[] passwordWithDelim = new byte[password.length + 1];
      System.arraycopy(password, 0, passwordWithDelim, 0, password.length);
      passwordWithDelim[password.length] = '\000';
      try {
         if (salt == null || rounds == 0) {
            salt = createNewSalt();
            rounds = determineBestRounds();
         }

         /* Adjust the length of the plaintext to the required keylength */

         int plaintext[] = { 0x155cbf8e, 0x57f57513, 0x3da787b9, 0x71679d82, 0x7cf72e93, 0x1ae25274, 0x64b54adc,
               0x335cbd0b };
         if (keylength < 256) {
            plaintext = Arrays.copyOf(plaintext, keylength / 32); // shorten the
                                                                  // key
         }

         BCrypt bcrypt = new BCrypt();
         byte[] rawBytes = bcrypt.crypt_raw(passwordWithDelim, salt, rounds, plaintext);
         SecretKeySpec spec = new SecretKeySpec(rawBytes, KEY_FACTORY);
         info.encryptCipher = Cipher.getInstance(KEY_FACTORY);
         info.encryptCipher.init(Cipher.ENCRYPT_MODE, spec);

         info.decryptCipher = Cipher.getInstance(KEY_FACTORY);
         info.decryptCipher.init(Cipher.DECRYPT_MODE, spec);
         info.salt = salt;
         info.rounds = rounds;
      } catch (Exception ex) {
         logger.log(Level.SEVERE, "createCiphers", ex);
         System.exit(16);
      }
      logger.log(Level.FINE, "Time to create ciphers for " + rounds + " rounds : "
                  + (System.currentTimeMillis() - start) + "ms");
      return info;
   }

   /**
    * Create cipher from supplied password, salt and rounds and default key length.
    * 
    * @param password
    * @param salt
    * @param rounds
    * @return cipherInfo
    */
   public static CipherInfo createCiphers(byte[] password, byte[] salt, int rounds) {
      return createCiphers(password, salt, rounds, defaultKeyLength);
   }

   /**
    * Create cipher from supplied password, salt and rounds
    * 
    * @see CipherInfo createCiphers(byte[] password, byte[] salt, int rounds)
    * @param password
    * @param saltAndRounds
    * @return cipherInfo
    */
   public static CipherInfo createCiphers(byte[] password, SaltAndRounds saltAndRounds) {
      return createCiphers(password, saltAndRounds.salt, saltAndRounds.rounds);
   }

   /**
    * Create cipher from supplied password and rounds. A random salt will be generated.
    * 
    * @see CipherInfo createCiphers(byte[] password, int rounds)
    * @param password
    * @param rounds
    * @return cipherInfo
    */
   public static CipherInfo createCiphers(byte[] password, int rounds) {
      return createCiphers(password, createNewSalt(), rounds);
   }
   
   /**
    * @return max keylength allowed by system
    * @throws NoSuchAlgorithmException
    */
   public static int getMaximumKeyLength() throws NoSuchAlgorithmException {
      /* determine max key length allowed by security policy */
      return Cipher.getMaxAllowedKeyLength(KEY_FACTORY);
   }

   /**
    * For testing only
    * 
    * @param args
    * @throws UnsupportedEncodingException
    */
   public static void main(String[] args) throws UnsupportedEncodingException {

      long start = System.currentTimeMillis();

      try {
         CipherInfo cipherInfo = createCiphers("secretstring".getBytes("UTF-8"), null, 0);

         // Our cleartext
         byte[] cleartext = "This is another example".getBytes();

         // Encrypt the cleartext
         byte[] ciphertext = cipherInfo.encryptCipher.doFinal(cleartext);
         long time = System.currentTimeMillis() - start;

         System.out.println("Encrypted string: " + Strings.toHex(ciphertext));
         System.out.println("Time taken: " + time + " ms");

         start = System.currentTimeMillis();
         byte[] decryptedtext = cipherInfo.decryptCipher.doFinal(ciphertext);
         time = System.currentTimeMillis() - start;
         System.out.println("Decrypted string: " + new String(decryptedtext));
         System.out.println("Time taken: " + time + " ms");

      } catch (IllegalBlockSizeException e) {
         e.printStackTrace();
      } catch (BadPaddingException e) {
         e.printStackTrace();
      }
      System.exit(0);
   }
}
