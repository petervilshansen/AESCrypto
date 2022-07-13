using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;
using System.Security.Cryptography;
using System.Text;

namespace AESCrypto2021
{
    public static class AESUtil
    {
        public const int SALT_SIZE = 8; // size in bytes
        public const int NONCE_SIZE = 12; // size in bytes
        public const int KEY_SIZE = 32; // size in bytes = 256 bits
        public const int PBKDF2_ITERATIONS = 200001;
        public const int AUTH_TAG_SIZE = 16;
        private const int PASSWORD_LENGTH = 25; // length of automatically generated secure password
        private const string TOKEN_DELIMITER = ".";

        internal static string CreatePassword(int length)
        {
            if (length % 5 != 0)
            {
                throw new ArgumentException("Password length must be a multiple of 5 in order to facilitate pretty-printing.");
            }
            const string valid = "abcdefghijkmnopqrstuvwxyz";
            StringBuilder res = new StringBuilder();
            while (0 < length--)
            {
                res.Append(valid[RandomNumberGenerator.GetInt32(valid.Length)]);
                if (length % 5 == 0 && length > 0)
                {
                    res.Append("-"); // pretty-print password for user
                }
            }
            return res.ToString();
        }
        internal static byte[] deriveEnryptionKey(string clearTextPassword, Span<byte> salt)
        {
            // Rfc2898DeriveBytes has been replaced in .NET 6.0:
            // https://docs.microsoft.com/en-us/aspnet/core/security/data-protection/consumer-apis/password-hashing?view=aspnetcore-6.0
            byte[] encryptionKey = KeyDerivation.Pbkdf2(clearTextPassword, salt.ToArray(), KeyDerivationPrf.HMACSHA256, PBKDF2_ITERATIONS, KEY_SIZE);
            return encryptionKey;
        }

        public static string Encrypt(byte[] plainBytes)
        {
            if (plainBytes == null || plainBytes.Length == 0) { throw new Exception("Plaintext cannot be null or empty."); }

            // Generate secure nonce and salt
            var salt = RandomNumberGenerator.GetBytes(SALT_SIZE);
            var nonce = RandomNumberGenerator.GetBytes(NONCE_SIZE);
            var cipherBytes = new byte[plainBytes.AsSpan().Length];
            var authTag = new byte[AUTH_TAG_SIZE];

            // Encrypt
            string randomPassword = CreatePassword(PASSWORD_LENGTH);
            Console.WriteLine("Automatically generated secure password (write this down): " + randomPassword);
         
            var derivedEncryptionKey = deriveEnryptionKey(randomPassword, salt);
            using (var aes = new AesGcm(derivedEncryptionKey))
            {
                aes.Encrypt(nonce, plainBytes.AsSpan(), cipherBytes, authTag);
            }

            // Encode to Base64 for easy transmission
            return Convert.ToBase64String(salt) + TOKEN_DELIMITER + Convert.ToBase64String(nonce) + TOKEN_DELIMITER + Convert.ToBase64String(cipherBytes) + TOKEN_DELIMITER + Convert.ToBase64String(authTag);
        }


        public static byte[] Decrypt(string cipherText, string clearTextPassword)
        {
            // Decode
            var tokens = cipherText.Split(TOKEN_DELIMITER);
            if (tokens.Length != 4)
            {
                throw new Exception("Bad encrypted data -- expected encrypted data format is: <SALT>.<NONCE>.<CIPHER_TEXT>.<AUTH_TAG> (all Base64-encoded).");
            }

            // Extract parameters
            var salt = Convert.FromBase64String(tokens[0]).AsSpan();
            var nonce = Convert.FromBase64String(tokens[1]).AsSpan();
            var cipherBytes = Convert.FromBase64String(tokens[2]).AsSpan();
            var authTag = Convert.FromBase64String(tokens[3]).AsSpan();

            // Decrypt
            Span<byte> plainBytes = new byte[cipherBytes.Length];
            byte[] derivedKey = deriveEnryptionKey(clearTextPassword, salt);
            using var aes = new AesGcm(derivedKey);
            aes.Decrypt(nonce, cipherBytes, authTag, plainBytes);

            return plainBytes.ToArray();
        }
    }
}
