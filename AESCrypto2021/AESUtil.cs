using Konscious.Security.Cryptography;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

namespace AESCrypto2021
{
    public static class AESUtil
    {
        public const int SALT_SIZE = 8; // size in bytes
        public const int NONCE_SIZE = 12; // size in bytes
        public const int KEY_SIZE = 32; // size in bytes = 256 bits
        public const int PBKDF2_ITERATIONS = 200001;
        public const int AUTH_TAG_SIZE = 16;
        private const string TOKEN_DELIMITER = ".";

        internal static string CreatePassword()
        {
            // Generate a 256-bit cryptographically strong AES key and hex-encode it for easy copying and pasting.
            byte[] randomBytes = RandomNumberGenerator.GetBytes(32);
            return BitConverter.ToString(randomBytes, 0, randomBytes.Length).Replace("-", "");
        }
        internal static byte[] deriveEnryptionKey(string password, byte[] salt)
        {
            using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password));
            argon2.Salt = salt;
            argon2.DegreeOfParallelism = 8;
            argon2.Iterations = 4;
            argon2.MemorySize = 1024 * 128;

            return argon2.GetBytes(32);
        }

        public static (string cipherText, string password) Encrypt(byte[] plainBytes)
        {
            if (plainBytes == null || plainBytes.Length == 0) { throw new Exception("Plaintext cannot be null or empty."); }

            string cipherText;
            string password;

            try
            {
                // Generate secure nonce and salt
                var salt = RandomNumberGenerator.GetBytes(SALT_SIZE);
                var nonce = RandomNumberGenerator.GetBytes(NONCE_SIZE);
                var cipherBytes = new byte[plainBytes.AsSpan().Length];
                var authTag = new byte[AUTH_TAG_SIZE];

                // Encrypt
                password = CreatePassword();
                Console.WriteLine("Automatically generated secure password (write this down): " + password);
                Console.WriteLine();

                var derivedEncryptionKey = deriveEnryptionKey(password, salt);
                using (var aes = new AesGcm(derivedEncryptionKey))
                {
                    aes.Encrypt(nonce, plainBytes.AsSpan(), cipherBytes, authTag);
                }

                // Encode to Base64 for easy transmission
                cipherText = Convert.ToBase64String(salt) + TOKEN_DELIMITER + Convert.ToBase64String(nonce) + TOKEN_DELIMITER + Convert.ToBase64String(cipherBytes) + TOKEN_DELIMITER + Convert.ToBase64String(authTag);
            }
            catch (Exception ex)
            {
                throw new Exception("Error during encryption: " + ex.Message);
            }

            return (cipherText, password);
        }


        public static byte[] Decrypt(string cipherText, string password)
        {
            // Decode
            var tokens = cipherText.Split(TOKEN_DELIMITER);
            if (tokens.Length != 4)
            {
                throw new Exception("Error during decryption: Bad encrypted data -- expected encrypted data format is: <SALT>.<NONCE>.<CIPHER_TEXT>.<AUTH_TAG> (all Base64-encoded).");
            }

            Span<byte> plainBytes;

            try
            {
                // Extract parameters
                var salt = Convert.FromBase64String(tokens[0]).AsSpan();
                var nonce = Convert.FromBase64String(tokens[1]).AsSpan();
                var cipherBytes = Convert.FromBase64String(tokens[2]).AsSpan();
                var authTag = Convert.FromBase64String(tokens[3]).AsSpan();

                // Decrypt
                plainBytes = new byte[cipherBytes.Length];
                byte[] derivedKey = deriveEnryptionKey(password, salt.ToArray());
                using var aes = new AesGcm(derivedKey);

                aes.Decrypt(nonce, cipherBytes, authTag, plainBytes);
            }
            catch (Exception ex)
            {
                throw new Exception("Error during decryption: " + ex.Message);
            }

            return plainBytes.ToArray();
        }
    }
}
