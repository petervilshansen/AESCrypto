using Konscious.Security.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AESCrypto
{
    internal class Argon2
    {
        public const int AES_KEY_SIZE_BYTES = 32; // size in bytes = 256 bits
        private const int DEGREE_OF_PARALLELLISM = 4; // four cores; should be twice the amount of available CPU cores dedicated to hashing
        private const int NUMBER_OF_ITERATIONS = 2; // two iterations
        private const int MEMORY_TO_USE_KILOBYTES = 1048576; // in 1KB increments; 1048576 = 1 GB
        internal static byte[] deriveEnryptionKey(string password, byte[] salt)
        {
            using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password));
            argon2.Salt = salt;
            argon2.DegreeOfParallelism = DEGREE_OF_PARALLELLISM;
            argon2.Iterations = NUMBER_OF_ITERATIONS;
            argon2.MemorySize = MEMORY_TO_USE_KILOBYTES;

            Console.WriteLine("Hashing password with Argon2id, this could take a moment...");
            return argon2.GetBytes(AES_KEY_SIZE_BYTES);
        }
    }
}
