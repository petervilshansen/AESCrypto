using Konscious.Security.Cryptography;
using System;
using System.Text;

namespace AESCrypto
{
    public class Argon2
    {
        public const int SALT_SIZE_BYTES = 16; // T = desired number of returned bytes; recommended size is 128 bits
        
        /**
         * Increasing the parallelism parameter in Argon2i allows the algorithm to use more CPU cores simultaneously,
         * which can improve performance on multi-core systems. However, it has a nuanced effect on security:
         *
         *   Performance: Higher parallelism can reduce the time required to compute the hash, making it faster for legitimate users.
         *
         *   Memory Usage: Increasing parallelism also increases the total memory usage, as each thread requires its own memory space. 
         *   This can make it more difficult for attackers to perform parallel attacks, especially on systems with limited memory.
         *
         *   Attack Resistance: While higher parallelism can improve performance, it doesn't significantly impact the overall security 
         *   of the algorithm. The memory-hard nature of Argon2i ensures that increasing parallelism doesn't make it easier for attackers 
         *   to crack the hash.
         *
         *   In summary, increasing the parallelism parameter can improve performance without compromising security, as long as the memory 
         *   cost is also appropriately set. This balance ensures that the algorithm remains resistant to attacks while providing efficient 
         *   performance for legitimate users.
         */
        public const int DEGREE_OF_PARALLELLISM = 4; // p = parallellism

        /**
         * Increasing the iterations parameter in Argon2i has a significant impact on security and performance:
         * 
         *   Security: More iterations increase the computational cost for an attacker, making it more difficult and time-consuming 
         *   to crack the hash.Each additional iteration requires the attacker to perform the hashing process multiple times, which 
         *   greatly enhances security.
         *
         *   Performance: Higher iterations also increase the time required to compute the hash for legitimate users. This can lead to 
         *   slower performance, especially if the iterations are set too high. It's important to find a balance that provides strong 
         *   security without causing noticeable delays for users.
         *
         *   A common recommendation is to start with 3 iterations and adjust based on your specific needs and the performance capabilities 
         *   of your system.By carefully tuning the iterations parameter, you can achieve a balance that maximizes security while 
         *   maintaining acceptable performance for users.
         */
        public const int NUMBER_OF_ITERATIONS = 3; // t = iterations

        /**
         * Increasing the memory parameter in Argon2i has a significant impact on both security and performance:
         * 
         *   Security: Higher memory usage makes it more difficult for attackers to perform parallel attacks, as they need to allocate 
         *   more memory for each attempt. This increases the cost and complexity of an attack, enhancing security.
         *   
         *   Performance: Increasing the memory parameter also increases the time required to compute the hash for legitimate users. 
         *   This can lead to slower performance, especially on systems with limited memory. However, the impact on performance is 
         *   generally less severe than increasing the iterations parameter.
         *   
         *   A good starting point for the memory parameter is 64 MiB (65536 KiB), but you can adjust this based on your system's 
         *   capabilities and security requirements. By carefully tuning the memory parameter, you can achieve a balance that maximizes 
         *   security while maintaining acceptable performance for users.
         *   
         *   The NVIDIA Hopper H100 GPU, the fastest GPU currently available (December 2024), is equipped with 80 GB of HBM3 memory.
         *   This GPU is equipped with 128 FP32 CUDA cores per Streaming Multiprocessor (SM) and a total of 18,432 FP32 CUDA cores.
         *   That yields a total of 80,000,000,000 bytes of memory / 18,432 cores = 4,340,277 ~= 4 MB of memory per core.
         */
        public const int MEMORY_TO_USE_KILOBYTES = 64*1024; // m = amount of memory, in 1KB increments.

        public static byte[] deriveEnryptionKey(string password, byte[] salt)
        {
            using var argon2 = new Argon2i(Encoding.UTF8.GetBytes(password));
            argon2.Salt = salt;
            argon2.DegreeOfParallelism = DEGREE_OF_PARALLELLISM;
            argon2.Iterations = NUMBER_OF_ITERATIONS;
            argon2.MemorySize = MEMORY_TO_USE_KILOBYTES;

            Console.WriteLine("Hashing password with Argon2i, this could take a moment...");
            byte[] derivedBytes = argon2.GetBytes(AESUtil.KEY_SIZE_BYTES);
            return derivedBytes;
        }
    }
}
