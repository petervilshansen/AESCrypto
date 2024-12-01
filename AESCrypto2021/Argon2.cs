using Konscious.Security.Cryptography;
using System;
using System.Text;

namespace AESCrypto
{
    public class Argon2
    {
        public const int SALT_SIZE_BYTES = 16; // size in bytes; recommended size is 128 bits
        public const int DEGREE_OF_PARALLELLISM = 4; // four cores; should be twice the amount of available CPU cores dedicated to hashing
        public const int NUMBER_OF_ITERATIONS = 2; // two iterations
        public const int MEMORY_TO_USE_KILOBYTES = 1048576; // in 1KB increments; 1048576 = 1 GB

        internal static byte[] deriveEnryptionKey(string password, byte[] salt)
        {
            using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password));
            argon2.Salt = salt;
            argon2.DegreeOfParallelism = DEGREE_OF_PARALLELLISM;
            argon2.Iterations = NUMBER_OF_ITERATIONS;
            argon2.MemorySize = MEMORY_TO_USE_KILOBYTES;

            Console.WriteLine("Hashing password with Argon2id, this could take a moment...");
            return argon2.GetBytes(AESUtil.KEY_SIZE_BYTES);
        }
    }
}
