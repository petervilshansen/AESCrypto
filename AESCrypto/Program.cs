using System;
using System.IO;
using System.Text;

namespace AESCrypto
{
    class Program
    {

        internal const string usageText =
            """
            AESCrypto - Copyright (c) Peter Vils Hansen <peter.vils.hansen@outlook.com>
            
            Easily encrypt data with AES-AESUtil.KEY_SIZE_BYTES*8-GCM using cryptographically secure, random passwords. 
 
            A secure password will be generated for you automatically. It is not possible to input your own password. 
 
            Usage: 
                Encrypt file 'secret.txt': AESCrypto -ef input.txt output.txt 
                Decrypt file 'encrypted.json': AESCrypto -df encrypted.json decrypted.json 
 
            Technical details: 
                AESCrypto encrypts data using AES-256 bit encryption in GCM mode. A secure password is automatically 
                generated using a cryptographically secure pseudo-random number generator. This password is then put
                through the Argon2i key derivation function.
 
            Data format: 
                +------------------------------------------------------------------------------------------------+ 
                | Salt (16 bytes) | Nonce (12 bytes) | Ciphertext (= input size) | Authentication tag (16 bytes) | 
                +------------------------------------------------------------------------------------------------+ 
 
            Example input (plaintext):

                Password: 4y9zw-4mv3j-su33k-cfvpb-sacqr

                00000000  54 68 65 20 4d 61 67 69  63 20 57 6f 72 64 73 20  |The Magic Words |
                00000010  61 72 65 20 53 71 75 65  61 6d 69 73 68 20 4f 73  |are Squeamish Os|
                00000020  73 69 66 72 61 67 65 0a                           |sifrage.|
                00000028

            Example output (ciphertext):

                00000000  44 89 02 16 a4 4a 61 09  61 a0 06 e9 d0 85 15 1c  |D....Ja.a.......|
                00000010  16 a4 a4 5f b7 7f 52 d2  13 c4 c6 50 fb e3 6a 95  |..._..R....P..j.|
                00000020  56 79 80 64 cd 86 c1 14  e1 68 83 c1 12 8b 40 41  |Vy.d.....h....@A|
                00000030  f7 41 1d b4 f4 64 73 84  d9 d1 91 c1 42 55 45 3e  |.A...ds.....BUE>|
                00000040  d3 a2 e0 1f 31 5e 5e c9  46 ec 7c 53 6e 91 6d 6c  |....1^^.F.|Sn.ml|
                00000050  82 72 5d 18                                       |.r].|

                - Salt is {44 89 ... 15 1c} = 16 bytes.
                - Nonce is {16 a4 ... c6 50} = 12 bytes.
                - Ciphertext is {fb e3 ... e0 1f} = 40 bytes.
                - Authentication tag is {31 5e ... 5d 18} = 16 bytes.

                Salt is input to Argon2i, nonce is used an initialisation vector for AES-GCM.
                Argon2i parameters: m = 65,536 kilobytes (128 MB), p = 1, and t = 2. 
 
            Github: 
                https://github.com/petervilshansen/AESCrypto 

            """;
        static void Main(string[] args)
        {
            CheckCommandLineArguments(args);

            if (Console.IsInputRedirected)
            {
                Console.WriteLine("Input redirected is not supported. Please try again without redirecting input via pipes.");
                return;
            }

            string operation = args[0].ToLower();

            try
            {
                if ("-ef".Equals(operation))
                {
                    if (args.Length < 3 || string.IsNullOrEmpty(args[1]) || string.IsNullOrEmpty(args[2]))
                    {
                        throw new ArgumentException("Input file name or output file name is missing -- aborting...");
                    }
                    string inputFileName = args[1];
                    string outputFileName = args[2];
                    EncryptFileInput(inputFileName, outputFileName);
                }
                else if ("-df".Equals(operation))
                {
                    if (args.Length < 3 || string.IsNullOrEmpty(args[1]) || string.IsNullOrEmpty(args[2]))
                    {
                        throw new ArgumentException("Input file name or output file name is missing -- aborting...");
                    }
                    string password = readPassphraseFromConsole();
                    string inputFileName = args[1];
                    string outputFileName = args[2];
                    DecryptFileInput(inputFileName, outputFileName, password);
                }
                else
                {
                    PrintUsage();
                }
            } catch (Exception ex)
            {
                Console.WriteLine("Operation failed with message: " + ex.Message);
            }
        }

        private static void DecryptFileInput(string inputFileName, string outputFileName, string password)
        {
            byte[] decrypted = AESUtil.Decrypt(File.ReadAllBytes(inputFileName), password);
            if (decrypted == null)
            {
                return;
            }
            File.WriteAllBytes(outputFileName, decrypted);
        }

        private static void EncryptFileInput(string inputFileName, string outputFileName)
        {
            (byte[] cipherText, string password) = AESUtil.Encrypt(File.ReadAllBytes(inputFileName));
            File.WriteAllBytes(outputFileName, cipherText);
        }

        private static void CheckCommandLineArguments(string[] args)
        {
            if (args == null || args.Length != 1 && args.Length != 3) { PrintUsage(); }
            if (args.Length == 1 && !(args[0].ToLower().Equals("-ec") || args[0].ToLower().Equals("-dc"))) PrintUsage();
            if (args.Length == 3 && !(args[0].ToLower().Equals("-ef") || args[0].ToLower().Equals("-df"))) PrintUsage();
        }

        private static void PrintUsage()
        {
            Console.WriteLine(usageText);
            Environment.Exit(0);
        }

        static string readPassphraseFromConsole()
        {
            string passPhrase = "";
            Console.Write("Input your pass phrase - finish with Enter: ");
            do
            {
                ConsoleKeyInfo key = Console.ReadKey(true);
                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    passPhrase += key.KeyChar;
                    Console.Write("*");
                }
                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    break;
                }
            } while (true);

            if (string.IsNullOrEmpty(passPhrase))
            {
                throw new ArgumentException("Empty pass phrase -- aborting...");
            }

            return passPhrase;
        }
    }
}
