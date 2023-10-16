using Konscious.Security.Cryptography;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Collections;

namespace AESCrypto2021
{
    public static class AESUtil
    {
        public const int Argon2idSaltSizeInBytes = 16; // size in bytes
        public const int AesKeySizeInBytes = 16; // size in bytes = 256 bits
        private const string TokenDelimiter = ".";
        private const int DegreeOfParallelism = 8; // four cores
        private const int NumberOfIterations = 4; // four iterations
        private const int MemoryToUseInKB = 1024 * 1024; // 1 GB
        private const int PasswordLength = 16;

        /*
            How long should my password be? Read this post by Jeremi Gosney:
            https://social.vivaldi.net/@epixoip@infosec.exchange/109748395816081877

                "At a hashrate of 1 PH/s (10^15 hash calculations per second) it would take more than 1627
                years to crack a random 13 character password (95^13). 

                https://www.wolframalpha.com/input?i=k+%3D+95%5E13%2C+r+%3D+10%5E15%2C+s+%3D+31536000%2C+y+%3D+k+%2Fr+%2F+s​

                For reference, the largest cluster we ever built at Terahash for a nation state client was "only" 
                capable of 8 TH/s (8 x 10^13 hash calculations per second) against a single unsalted MD5 hash. To achieve
                1 PH/s on raw MD5 today, you would need a cluster of 6250 x RTX 4090 GPUs.

                Let's look at it from another angle: to crack a random 13 character password in less than 100 years, you 
                would need an average hashrate of 16.3 PH/s (1.63 x 10^16 hash calculations per second.) 

                https://www.wolframalpha.com/input?i=k+%3D+95%5E13%2C+s+%3D+31536000%2C+100+%3D+k+%2Fr+%2F+s

                To achieve this today against raw MD5, you would need a cluster of 101738 x RTX 4090 GPUs. And this is 
                just for raw MD5, not 100k rounds of PBKDF2 like your master password is hashed with."

            In other words: Using a 16-character password (94^16, a number more than 700,000 times larger than 95^13)
            will not be broken in the foreseeable future. Using the same calculation as above, a random 16-character 
            password (94^16) would take more than 1.2 billion years to crack, again not including the Argon2id hashing.

        */
        internal static string CreatePasswordPrintableAscii()
        {
            // Create a pool of all printable ASCII characters, excluding space (ASCII 33 - ASCII 126).
            var pool = Enumerable.Range(33, 94).Select(x => (char)x).ToArray();

            var password = new StringBuilder();
            for (int i = 0; i < PasswordLength; i++)
            {
                password.Append(pool[RandomNumberGenerator.GetInt32(pool.Length)]);
            }

            return password.ToString();
        }
        internal static string CreatePasswordHexEncoded()
        {
            // Generate a cryptographically strong AES key and hex-encode it for easy copying and pasting.
            byte[] randomBytes = RandomNumberGenerator.GetBytes(AesKeySizeInBytes);
            return BitConverter.ToString(randomBytes, 0, randomBytes.Length).Replace("-", "");
        }
        internal static byte[] deriveEnryptionKey(string password, byte[] salt)
        {
            using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password));
            argon2.Salt = salt;
            argon2.DegreeOfParallelism = DegreeOfParallelism;
            argon2.Iterations = NumberOfIterations;
            argon2.MemorySize = MemoryToUseInKB;

            return argon2.GetBytes(AesKeySizeInBytes);
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
                Console.WriteLine("Generating secure password...");
                password = CreatePasswordPrintableAscii();

                Console.WriteLine("Automatically generated secure password (write this down): " + password);

                Console.WriteLine("Hashing password with Argon2id, this could take a moment...");
                byte[] encryptionKeySalt = RandomNumberGenerator.GetBytes(Argon2idSaltSizeInBytes);
                var encryptionKey = deriveEnryptionKey(password, encryptionKeySalt);

                using (var aes = new AesGcm(encryptionKey))
                {
                    Console.WriteLine("Encrypting...");
                    var aesGcmNonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
                    var cipherTextBytes = new byte[plainTextBytes.AsSpan().Length];
                    var aesGcmAuthTag = new byte[AesGcm.TagByteSizes.MaxSize];
                    aes.Encrypt(aesGcmNonce, plainTextBytes.AsSpan(), cipherTextBytes, aesGcmAuthTag);

                    // Encode to Base64 for easy transmission
                    cipherText = Convert.ToBase64String(encryptionKeySalt) + TokenDelimiter + Convert.ToBase64String(aesGcmNonce) + TokenDelimiter + Convert.ToBase64String(cipherTextBytes) + TokenDelimiter + Convert.ToBase64String(aesGcmAuthTag);
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
            var tokens = cipherText.Split(TokenDelimiter);
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

                Console.WriteLine("Hashing password with Argon2id, this could take a moment...");
                var encryptionKey = deriveEnryptionKey(password, salt.ToArray());
                using (var aes = new AesGcm(encryptionKey))
                {
                    Console.WriteLine("Decrypting...");
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
