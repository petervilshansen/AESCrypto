using System;
using System.IO;
using System.Text;
using System.Text.Json;

namespace AESCrypto2021
{
  class Program
  {
    private static readonly JsonSerializerOptions jsonOptions = new JsonSerializerOptions
    {
      IgnoreNullValues = true,
      WriteIndented = true
    };

    static void Main(string[] args)
    {
      CheckCommandLineArguments(args);

      if (args[0].ToLower().Equals("-ec"))
      {
        string password = args[1];
        EncryptConsoleInput(password);
      }
      else if (args[0].ToLower().Equals("-ef"))
      {
        string password = args[1];
        string inputFileName = args[2];
        string outputFileName = args[3];
        EncryptFileInput(inputFileName, outputFileName, password);
      }
      else if (args[0].ToLower().Equals("-dc"))
      {
        string password = args[1];
        DecryptConsoleInput(password);
      }
      else if (args[0].ToLower().Equals("-df"))
      {
        string password = args[1];
        string inputFileName = args[2];
        string outputFileName = args[3];
        DecryptFileInput(inputFileName, outputFileName, password);
      }
      else
      {
        printUsage();
      }
    }

    private static void DecryptFileInput(string inputFileName, string outputFileName, string password)
    {
      byte[] decrypted = AESUtil.Decrypt(File.ReadAllText(inputFileName), password);
      File.WriteAllBytes(outputFileName, decrypted);
    }

    private static void DecryptConsoleInput(string password)
    {
      string encrypted = readInputFromConsole();
      string decrypted = Encoding.UTF8.GetString(AESUtil.Decrypt(encrypted, password));
      Console.WriteLine(decrypted);
    }

    private static void EncryptFileInput(string inputFileName, string outputFileName, string password)
    {
      string encryptedBase64 = AESUtil.Encrypt(File.ReadAllBytes(inputFileName), password);
      File.WriteAllText(outputFileName, encryptedBase64);
    }

    private static void EncryptConsoleInput(string password)
    {
      string encrypted = AESUtil.Encrypt(readInputFromConsole(), password);
      Console.WriteLine(encrypted);
    }

    private static void CheckCommandLineArguments(string[] args)
    {
      if (args == null || args.Length < 2 || args.Length > 4) printUsage();
      if (args.Length == 2 && !(args[0].ToLower().Equals("-ec") || args[0].ToLower().Equals("-dc"))) printUsage();
      if (args.Length == 3 && !(args[0].ToLower().Equals("-ef") || args[0].ToLower().Equals("-df"))) printUsage();
    }

    private static void printUsage()
    {
      Console.WriteLine(
        "\n" +
        "Usage: AESCrypto2021 -ec <password> <input>\n" +
        "   or: AESCrypto2021 -dc <password> <input>\n" +
        "   or: AESCrypto2021 -ef <password> <input file> <output file>\n" +
        "   or: AESCrypto2021 -df <password> <input file> <output file>\n" +
        "Examples:\n" +
        "    Encrypt input from console with password 'foo' (end input with Ctrl+Z, Enter): AESCrypto2021 -ec foo\n" +
        "    Decrypt input from console with password 'foo' (end input with Ctrl+Z, Enter): AESCrypto2021 -dc foo\n" +
        "    Encrypt input from console piped in with password 'bar': echo Hello World | AESCrypto2021 -ec bar\n" +
        "    Decrypt input from console piped in with password 'bar': type secret.json | AESCrypto2021 -dc bar\n" +
        "    Encrypt file 'secret.txt' with password 'jazz': AESCrypto2021 -ef jazz secret.txt encrypted-secret.json\n" +
        "    Decrypt file 'encrypted-secret.json' with password 'jazz': AESCrypto2021 -df jazz encrypted-secret.json secret.txt"
        );
      Environment.Exit(0);
    }

    static string readInputFromConsole()
    {
      string line;
      string input = "";
      while ((line = Console.ReadLine()) != null) { input += line + "\n"; }
      return input;
    }
  }
}
