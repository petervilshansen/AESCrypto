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

        internal static string CreatePasswordPrintableAscii()
        {
            // Create a pool of all printable ASCII characters, range ASCII 33 - ASCII 126.
            var pool = Enumerable.Range(33, 93).Select(x => (char)x).ToArray();

            // log2(93 characters) ~= 6.5 bits per character.
            // 256 bits / 6.5 bits per character = 39 characters
            var password = new StringBuilder();
            for (int i = 0; i < 40; i++)
            {
                password.Append(pool[RandomNumberGenerator.GetInt32(pool.Length)]);
            }

            return password.ToString();
        }
        internal static string CreatePasswordHexEncoded()
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

        public static (string cipherText, string password) Encrypt(byte[] plainTextBytes)
        {
            if (plainTextBytes == null || plainTextBytes.Length == 0) { throw new Exception("Plaintext cannot be null or empty."); }

            string cipherText;
            string password;

            try
            {
                // Encrypt
                //password = CreatePasswordHexEncoded();
                password = CreatePasswordPrintableAscii();
                Console.WriteLine("Automatically generated secure password (write this down): " + password);

                byte[] encryptionKeySalt = RandomNumberGenerator.GetBytes(SALT_SIZE);
                var encryptionKey = deriveEnryptionKey(password, encryptionKeySalt);
                
                using (var aes = new AesGcm(encryptionKey))
                {
                    var aesGcmNonce = RandomNumberGenerator.GetBytes(NONCE_SIZE);
                    var cipherTextBytes = new byte[plainTextBytes.AsSpan().Length];
                    var aesGcmAuthTag = new byte[AUTH_TAG_SIZE];
                    aes.Encrypt(aesGcmNonce, plainTextBytes.AsSpan(), cipherTextBytes, aesGcmAuthTag);

                    // Encode to Base64 for easy transmission
                    cipherText = Convert.ToBase64String(encryptionKeySalt) + TOKEN_DELIMITER + Convert.ToBase64String(aesGcmNonce) + TOKEN_DELIMITER + Convert.ToBase64String(cipherTextBytes) + TOKEN_DELIMITER + Convert.ToBase64String(aesGcmAuthTag);
                }
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

                var encryptionKey = deriveEnryptionKey(password, salt.ToArray());
                using (var aes = new AesGcm(encryptionKey))
                {
                    plainBytes = new byte[cipherBytes.Length];
                    aes.Decrypt(nonce, cipherBytes, authTag, plainBytes);
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Error during decryption: " + ex.Message);
            }

            return plainBytes.ToArray();
        }
    }
}
