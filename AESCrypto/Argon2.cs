using Konscious.Security.Cryptography;
using System;
using System.Text;
using System.Timers;

namespace AESCrypto
{
    public class Argon2
    {
        public const int SALT_SIZE_BYTES = 16; // T = desired number of returned bytes; recommended size is 128 bits
        public const int DEGREE_OF_PARALLELLISM = 1; // p = degree of parallellism; fixed at 1 for all recommendations I've seen
        public const int NUMBER_OF_ITERATIONS = 4; // t = iterations
        public const int MEMORY_TO_USE_KILOBYTES = 128*1024; // m = amount of memory, in 1KB increments.

        public static byte[] deriveEnryptionKey(string password, byte[] salt)
        {
            using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password));
            argon2.Salt = salt;
            argon2.DegreeOfParallelism = DEGREE_OF_PARALLELLISM;
            argon2.Iterations = NUMBER_OF_ITERATIONS;
            argon2.MemorySize = MEMORY_TO_USE_KILOBYTES;

            Console.WriteLine("Hashing password with Argon2id, this could take a moment...");
            var watch = System.Diagnostics.Stopwatch.StartNew();
            byte[] derivedBytes = argon2.GetBytes(AESUtil.KEY_SIZE_BYTES);
            watch.Stop();
            var elapsedMs = watch.ElapsedMilliseconds;
            Console.WriteLine("Argon2id completed in " +  elapsedMs + " milliseconds.");
            return derivedBytes;
        }
    }
}
