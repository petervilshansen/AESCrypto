﻿using System;
using System.IO;
using System.Text;

namespace AESCrypto
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
            AesRecord aesRecord = AESUtil.Encrypt(File.ReadAllBytes(inputFileName));
            File.WriteAllText(outputFileName, Convert.ToBase64String(aesRecord.cipherText));
        }

        private static void EncryptConsoleInput(string plainText)
        {
            AesRecord aesRecord = AESUtil.Encrypt(plainText);
            Console.WriteLine();
            Console.WriteLine("--- BEGIN ENCRYPTED ---");
            Console.WriteLine(Convert.ToBase64String(aesRecord.payload));
            Console.WriteLine("--- BEGIN ENCRYPTED ---");
        }

        private static void CheckCommandLineArguments(string[] args)
        {
            if (args == null || args.Length != 1 && args.Length != 3) { PrintUsage(); }
            if (args.Length == 1 && !(args[0].ToLower().Equals("-ec") || args[0].ToLower().Equals("-dc"))) PrintUsage();
            if (args.Length == 3 && !(args[0].ToLower().Equals("-ef") || args[0].ToLower().Equals("-df"))) PrintUsage();
        }

        private static void PrintHeader() {
            Console.WriteLine("\nAESCrypto - Copyright (c) Peter Vils Hansen <peter.vils.hansen@outlook.com>\n");
        }

        private static void PrintUsage()
        {
            Console.WriteLine(
              "Easily encrypt data with AES-"+AESUtil.KEY_SIZE_BYTES*8+"-GCM using cryptographically secure, random passwords.\n" +
              "\n" +
              "A secure password will be generated for you automatically. It is not possible to input your own password.\n" +
              "\n" +
              "Usage:\n" +
              "    Encrypt input from console: AESCrypto -ec\n" +
              "    Decrypt input from console: AESCrypto -dc\n" +
              "    Encrypt file 'secret.txt': AESCrypto -ef input.txt output.txt\n" +
              "    Decrypt file 'encrypted.json': AESCrypto -df encrypted.json decrypted.json\n" +
              "\n" +
              "Technical details:\n" +
              "    AESCrypto encrypts data using AES-"+AESUtil.KEY_SIZE_BYTES*8+" bit encryption in GCM mode. A password with\n" +
              "    characters chosen from the pool of all printable ASCII characters except space (i.e., ASCII 33-126) is\n" +
              "    automatically generated using a cryptographically secure pseudo-random number generator. Further protection\n" +
              "    against brute-force attacks is achieved through use of the Argon2id key derivation function with parameters\n" +
              "    m="+Argon2.MEMORY_TO_USE_KILOBYTES+" KB, t="+Argon2.DEGREE_OF_PARALLELLISM+", and p="+Argon2.NUMBER_OF_ITERATIONS+", applied to the password prior to encryption.\n" +
              "\n" +
              "Data format:\n" +
              "    +------------------------------------------------------------------------------------------------+\n" +
              "    | Salt ("+Argon2.SALT_SIZE_BYTES+" bytes) | Nonce ("+AESUtil.NONCE_SIZE_BYTES+" bytes) | Ciphertext (= input size) | Authentication tag ("+AESUtil.TAG_SIZE_BYTES+" bytes) |\n" +
              "    +------------------------------------------------------------------------------------------------+\n" +
              "\n" +
              "    All output data is Base64-encoded. Salt is input to Argon2id, nonce is used an initialisation vector for AES-GCM.\n" +
              "\n" +
              "Github:\n" +
              "    https://github.com/petervilshansen/AESCrypto" +
              "\n"
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
