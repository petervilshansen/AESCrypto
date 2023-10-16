using System;
using System.IO;
using System.Text;

namespace AESCrypto2021
{
    class Program
    {
        static void Main(string[] args)
        {
            PrintHeader();

            CheckCommandLineArguments(args);

            if (Console.IsInputRedirected)
            {
                Console.WriteLine("Input redirected is not supported. Please try again without redirecting input via pipes.");
                return;
            }

            string operation = args[0].ToLower();

            try
            {
                if ("-ec".Equals(operation))
                {
                    string plainText = readInputFromConsole();
                    EncryptConsoleInput(plainText);
                }
                else if ("-ef".Equals(operation))
                {
                    if (args.Length < 3 || string.IsNullOrEmpty(args[1]) || string.IsNullOrEmpty(args[2]))
                    {
                        throw new ArgumentException("Input file name or output file name is missing -- aborting...");
                    }
                    string inputFileName = args[1];
                    string outputFileName = args[2];
                    EncryptFileInput(inputFileName, outputFileName);
                }
                else if ("-dc".Equals(operation))
                {
                    string cipherText = readInputFromConsole();
                    DecryptConsoleInput(cipherText);
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
            byte[] decrypted = AESUtil.Decrypt(File.ReadAllText(inputFileName), password);
            if (decrypted == null)
            {
                return;
            }
            File.WriteAllBytes(outputFileName, decrypted);
        }

        private static void DecryptConsoleInput(string cipherText)
        {
            string password = readPassphraseFromConsole();
            string decrypted = Encoding.UTF8.GetString(AESUtil.Decrypt(cipherText, password));
            if (string.IsNullOrEmpty(decrypted))
            {
                return;
            }
            Console.WriteLine();
            Console.WriteLine("--- BEGIN DECRYPTED ---");
            Console.WriteLine(decrypted);
            Console.WriteLine("--- END DECRYPTED ---");
        }

        private static void EncryptFileInput(string inputFileName, string outputFileName)
        {
            (string cipherTextBase64, string password) = AESUtil.Encrypt(File.ReadAllBytes(inputFileName));
            if (string.IsNullOrEmpty(cipherTextBase64))
            {
                return;
            }
            File.WriteAllText(outputFileName, cipherTextBase64);
        }

        private static void EncryptConsoleInput(string plainText)
        {
            (string cipherTextBase64, string password) = AESUtil.Encrypt(Encoding.UTF8.GetBytes(plainText));
            if (string.IsNullOrEmpty(cipherTextBase64))
            {
                return;
            }
            Console.WriteLine();
            Console.WriteLine("--- BEGIN ENCRYPTED ---");
            Console.WriteLine(cipherTextBase64);
            Console.WriteLine("--- BEGIN ENCRYPTED ---");
        }

        private static void CheckCommandLineArguments(string[] args)
        {
            if (args == null || args.Length != 1 && args.Length != 3) { PrintUsage(); }
            if (args.Length == 1 && !(args[0].ToLower().Equals("-ec") || args[0].ToLower().Equals("-dc"))) PrintUsage();
            if (args.Length == 3 && !(args[0].ToLower().Equals("-ef") || args[0].ToLower().Equals("-df"))) PrintUsage();
        }

        private static void PrintHeader() {
            Console.WriteLine("\nAESCrypto2021 - Copyright (c) Peter Vils Hansen <peter.vils.hansen@outlook.com>\n");
        }

        private static void PrintUsage()
        {
            Console.WriteLine(
              "Easily encrypt data with AES-128-GCM using cryptographically secure, random passwords.\n" +
              "\n" +
              "A secure password will be generated automatically. It is not possible to input your own password.\n" +
              "\n" +
              "Usage:\n" +
              "    Encrypt input from console: AESCrypto2021 -ec\n" +
              "    Decrypt input from console: AESCrypto2021 -dc\n" +
              "    Encrypt file 'secret.txt': AESCrypto2021 -ef secret.txt secret-output.txt\n" +
              "    Decrypt file 'encrypted-secret.json': AESCrypto2021 -df encrypted-secret.json decrypted-secret.json\n" +
              "\n" +
              "Technical details:\n" +
              "    AESCrypto2021 encrypts data using AES 128 bit encryption in GCM mode. A 16-character password with\n" +
              "    characters chosen from the pool of all printable ASCII characters except space (i.e., ASCII 33-126) is\n" +
              "    automatically generated using a cryptographically secure pseudo-random number generator. Further protection\n" +
              "    against brute-force attacks is achieved through use of the Argon2id key derivation function with parameters\n" +
              "    m=1GB, t=4, and p=8, applied to the password prior to encryption.\n" +
              "\n" +
              "Data format:\n" +
              "    +-------------------------------------------------------------------------------------------------+\n" +
              "    | Salt (8 bytes) | . | Nonce (12 bytes) | . | Ciphertext (= input size) | . | Auth tag (16 bytes) |\n" +
              "    +-------------------------------------------------------------------------------------------------+\n" +
              "\n" +
              "    Field separator is ASCII code 46 - period/dot/full stop (1 byte).\n" +
              "\n" +
              "Github:\n" +
              "    https://github.com/petervilshansen/AESCrypto2021"
              );
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

        static string readInputFromConsole()
        {
            Console.WriteLine("Input your message - press Return/Enter twice to finish...");
            string line;
            string input = "";
            do
            {
                line = Console.ReadLine();
                input += line;
            } while (line != null && line.Length > 0);

            if (string.IsNullOrEmpty(input))
            {
                throw new ArgumentException("Empty input -- aborting...");
            }

            return input;
        }
    }
}
