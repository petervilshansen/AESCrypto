using System;
using System.Security.Cryptography;
using System.Text;
using System.Linq;

namespace AESCrypto
{
    public static class AESUtil
    {
        public const int ARGON2ID_SALT_SIZE_BYTES = 16; // size in bytes; recommended size is 128 bits
        private const int PASSWORD_LENGTH = 40; // log2(94^40) = shortest password length that gives >= 256 bits of entropy
        private const int ASCII_PRINTABLE_LOW_CHAR = 33;
        private const int ASCII_NUM_PRINTABLE_CHARS = 93; // ASCII 33 -> 126

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
        internal static (string, int) CreatePasswordPrintableAscii()
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

        public static (string cipherText, string password) Encrypt(string plainText)
        {
            var plainTextBytes = new byte[Encoding.UTF8.GetBytes(plainText).Length];
            return Encrypt(plainTextBytes);
        }

        public static (string cipherText, string password) Encrypt(byte[] plainTextBytes)
        {
            if (plainTextBytes == null || plainTextBytes.Length == 0) { throw new Exception("Plaintext cannot be null or empty."); }

            string cipherText;
            string password;
            int entropy;

            try
            {
                // Encrypt
                Console.WriteLine("Generating secure password...");
                (password, entropy) = CreatePasswordPrintableAscii();

                Console.WriteLine("Automatically generated secure password (write this down): \n\n" + password + "\n\nEntropy: " + entropy + " bits.");

                byte[] argonSalt = RandomNumberGenerator.GetBytes(ARGON2ID_SALT_SIZE_BYTES);
                var encryptionKey = Argon2.deriveEnryptionKey(password, argonSalt);

                using (var aes = new AesGcm(encryptionKey, AesGcm.TagByteSizes.MaxSize))
                {
                    Console.WriteLine("Encrypting...");
                    
                    var nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
                    var cipherTextBytes = new byte[plainTextBytes.Length];
                    var tag = new byte[AesGcm.TagByteSizes.MaxSize];

                    aes.Encrypt(nonce, plainTextBytes, cipherTextBytes, tag);

                    // Encode to Base64 for easy transmission. Use Buffer.BlockCopy for best performance, according to https://code-maze.com/csharp-merge-arrays/
                    byte[] outputBytes = new byte[argonSalt.Length + nonce.Length + cipherTextBytes.Length + tag.Length];
                    
                    Buffer.BlockCopy(argonSalt, 0, outputBytes, 0, argonSalt.Length);
                    Buffer.BlockCopy(nonce, 0, outputBytes, argonSalt.Length, nonce.Length);
                    Buffer.BlockCopy(tag, 0, outputBytes, argonSalt.Length + nonce.Length, tag.Length);
                    Buffer.BlockCopy(cipherTextBytes, 0, outputBytes, argonSalt.Length + nonce.Length + tag.Length, cipherTextBytes.Length);

                    cipherText = Convert.ToBase64String(outputBytes.ToArray());
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Error during encryption: " + ex.Message);
            }

            return (cipherText, password);
        }


        public static byte[] Decrypt(string cipherTextInput, string password)
        {
            byte[] plainBytes;

            // Extract parameters
            byte[] cipherTextInputBytes = Convert.FromBase64String(cipherTextInput);
            byte[] argonSalt = new byte[ARGON2ID_SALT_SIZE_BYTES];
            byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
            byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];
            byte[] cipherTextBytes = new byte[cipherTextInputBytes.Length - argonSalt.Length - nonce.Length - tag.Length];

            try
            {
                Buffer.BlockCopy(cipherTextInputBytes, 0, argonSalt, 0, argonSalt.Length);
                Buffer.BlockCopy(cipherTextInputBytes, argonSalt.Length, nonce, 0, nonce.Length);
                Buffer.BlockCopy(cipherTextInputBytes, argonSalt.Length + nonce.Length, tag, 0, tag.Length);
                Buffer.BlockCopy(cipherTextInputBytes, argonSalt.Length + nonce.Length + tag.Length, cipherTextBytes, 0, cipherTextBytes.Length);

                var encryptionKey = Argon2.deriveEnryptionKey(password, argonSalt);

                using (var aes = new AesGcm(encryptionKey, AesGcm.TagByteSizes.MaxSize))
                {
                    Console.WriteLine("Decrypting...");
                    plainBytes = new byte[cipherTextBytes.Length];
                    aes.Decrypt(nonce, cipherTextBytes, tag, plainBytes);
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Error during decryption: " + ex.Message);
            }

            return plainBytes;
        }
    }
}
