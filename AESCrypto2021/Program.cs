using System;
using System.IO;
using System.Text;

namespace AESCrypto2021
{
    class Program
    {
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
                    printUsage();
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
            Console.WriteLine(decrypted);
        }

        private static void EncryptFileInput(string inputFileName, string outputFileName)
        {
            string encryptedBase64 = AESUtil.Encrypt(File.ReadAllBytes(inputFileName));
            if (string.IsNullOrEmpty(encryptedBase64))
            {
                return;
            }
            File.WriteAllText(outputFileName, encryptedBase64);
        }

        private static void EncryptConsoleInput(string plainText)
        {
            string encrypted = AESUtil.Encrypt(Encoding.UTF8.GetBytes(plainText));
            if (string.IsNullOrEmpty(encrypted))
            {
                return;
            }
            Console.WriteLine(encrypted);
        }

        private static void CheckCommandLineArguments(string[] args)
        {
            if (args == null || args.Length != 1 && args.Length != 3) printUsage();
            if (args.Length == 1 && !(args[0].ToLower().Equals("-ec") || args[0].ToLower().Equals("-dc"))) printUsage();
            if (args.Length == 3 && !(args[0].ToLower().Equals("-ef") || args[0].ToLower().Equals("-df"))) printUsage();
        }

        private static void printUsage()
        {
            Console.WriteLine(
              "\n" +
              "AESCrypto2021 - Copyright (c) 2022 Peter Vils Hansen <peter.vils.hansen@gmail.com>\n" +
              "\n" +
              "Easily encrypt data using AES-GCM with 256 bit key size. Password hashed using PBKDF2-HMAC-SHA-256 with 200,001 rounds.\n" +
              "\n" +
              "Usage: AESCrypto2021 -ec\n" +
              "   or: AESCrypto2021 -dc\n" +
              "   or: AESCrypto2021 -ef <input file> <output file>\n" +
              "   or: AESCrypto2021 -df <input file> <output file>\n" +
              "Examples:\n" +
              "    Encrypt input from console: AESCrypto2021 -ec\n" +
              "    Decrypt input from console: AESCrypto2021 -dc\n" +
              "    Encrypt file 'secret.txt': AESCrypto2021 -ef secret.txt secret-output.txt\n" +
              "    Decrypt file 'encrypted-secret.json': AESCrypto2021 -df secret-output.txt decrypted.txt\n" + 
              "\n" + 
              "    A secure password will be generated automatically. It is not possible to input your own password."
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
            Console.WriteLine("Input your message - finish with an empty line (= Enter twice)...");
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
