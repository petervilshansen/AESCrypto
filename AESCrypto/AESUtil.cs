using System;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Diagnostics.Metrics;

namespace AESCrypto
{
    public record AesRecord()
    {
        public string password { get; set; }
        public string plainText { get; set; }
        public byte[] salt { get; set; }
        public byte[] nonce { get; set; }
        public byte[] tag { get; set; }
        public byte[] cipherText { get; set; }
        public int entropy { get; set; }
        public byte[] payload { get; set; } // salt, nonce, ciphertext, and tag combined
    }

    public static class AESUtil
    {
        public const int KEY_SIZE_BYTES = 32; // size in bytes = 256 bits
        public const int PASSWORD_LENGTH = 40; // log2(94^40) = shortest password length that gives >= 256 bits of entropy
        public const int ASCII_PRINTABLE_LOW_CHAR = 33;
        public const int ASCII_NUM_PRINTABLE_CHARS = 93; // ASCII 33 -> 126
        public static readonly int TAG_SIZE_BYTES = AesGcm.TagByteSizes.MaxSize;
        public static readonly int NONCE_SIZE_BYTES = AesGcm.NonceByteSizes.MaxSize; // Note: AesGcm.NonceByteSizes.MinSize == AesGcm.NonceByteSizes.MaxSize == 12 bytes.

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
        internal static (string password, int entropy) CreatePasswordPrintableAscii()
        {
            // Create a pool of all printable ASCII characters, excluding space (ASCII 33 - ASCII 126).
            var pool = Enumerable.Range(ASCII_PRINTABLE_LOW_CHAR, ASCII_NUM_PRINTABLE_CHARS).Select(x => (char)x).ToArray();
            Console.WriteLine("Password character pool:");
            Console.WriteLine(pool);

            var password = new StringBuilder();
            for (int i = 0; i < PASSWORD_LENGTH; i++)
            {
                // Beware modulo bias!
                password.Append(pool[RandomNumberGenerator.GetInt32(pool.Length)]);
            }

            return ( password.ToString(), (int)Math.Floor(Math.Log2(Math.Pow(pool.Length, password.Length))) );
        }


        public static (byte[] cipherText, string password) Encrypt(byte[] plainText)
        {
            if (plainText == null || plainText.Length == 0) { throw new Exception("Plaintext cannot be null or empty."); }

            string password;
            int entropy;

            try
            {
                // Encrypt
                Console.WriteLine("Generating secure password...");
                (password, entropy) = CreatePasswordPrintableAscii();

                Console.WriteLine("Automatically generated secure password (write this down): \n\n" + password + "\n\nEntropy: " + entropy + " bits.");

                byte[] salt = RandomNumberGenerator.GetBytes(Argon2.SALT_SIZE_BYTES);
                byte[] derivedKey = Argon2.deriveEnryptionKey(password, salt);

                using (var aes = new AesGcm(derivedKey, TAG_SIZE_BYTES))
                {
                    Console.WriteLine("Encrypting...");

                    // The nonce does not have to be random, it can be a counter. But it absolutely must be unique for each message encrypted
                    // with the same key. Using GCM on two different messages with the same key and nonce basically allows an attacker to decrypt
                    // both messages and forge further messages.

                    byte[] nonce = RandomNumberGenerator.GetBytes(NONCE_SIZE_BYTES);
                    byte[] cipherText = new byte[plainText.Length];
                    byte[] tag = new byte[TAG_SIZE_BYTES];

                    aes.Encrypt(nonce, plainText, cipherText, tag);

                    // Encode to Base64 for easy transmission. Use Buffer.BlockCopy for best performance, according to https://code-maze.com/csharp-merge-arrays/
                    byte[] returnValue = new byte[salt.Length + nonce.Length + cipherText.Length + tag.Length];
                    
                    Buffer.BlockCopy(salt, 0, returnValue, 0, salt.Length);
                    Buffer.BlockCopy(nonce, 0, returnValue, salt.Length, nonce.Length);
                    Buffer.BlockCopy(tag, 0, returnValue, salt.Length + nonce.Length, tag.Length);
                    Buffer.BlockCopy(cipherText, 0, returnValue, salt.Length + nonce.Length + tag.Length, cipherText.Length);

                    return (returnValue, password);
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Error during encryption: " + ex.Message);
            }
        }

        public static byte[] Decrypt(byte[] cipherText, string password)
        {
            // Extract parameters
            try
            {
                byte[] salt = new byte[Argon2.SALT_SIZE_BYTES];
                byte[] nonce = new byte[NONCE_SIZE_BYTES];
                byte[] tag = new byte[TAG_SIZE_BYTES];
                byte[] body = new byte[cipherText.Length - salt.Length - nonce.Length - tag.Length];

                Buffer.BlockCopy(cipherText, 0, salt, 0, salt.Length);
                Buffer.BlockCopy(cipherText, salt.Length, nonce, 0, nonce.Length);
                Buffer.BlockCopy(cipherText, salt.Length + nonce.Length, tag, 0, tag.Length);
                Buffer.BlockCopy(cipherText, salt.Length + nonce.Length + tag.Length, body, 0, body.Length);

                var encryptionKey = Argon2.deriveEnryptionKey(password, salt);

                using (var aes = new AesGcm(encryptionKey, TAG_SIZE_BYTES))
                {
                    Console.WriteLine("Decrypting...");
                    byte[] plainBytes = new byte[body.Length];
                    aes.Decrypt(nonce, body, tag, plainBytes);

                    return plainBytes;
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Error during decryption: " + ex.Message);
            }
        }
    }
}
