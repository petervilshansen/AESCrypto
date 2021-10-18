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
        AESUtil.EncryptionMode encryptionMode = args[2].ToLower().Equals("cbc") ? AESUtil.EncryptionMode.CBC : AESUtil.EncryptionMode.GCM;
        EncryptConsoleInput(encryptionMode, password);
      }
      else if (args[0].ToLower().Equals("-ef"))
      {
        string encryptionModeParam = args[1];
        string password = args[2];
        string inputFileName = args[3];
        string outputFileName = args[4];
        AESUtil.EncryptionMode encryptionMode = encryptionModeParam.ToLower().Equals("cbc") ? AESUtil.EncryptionMode.CBC : AESUtil.EncryptionMode.GCM;
        EncryptFileInput(encryptionMode, inputFileName, outputFileName, password);
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
      var utf8Reader = new Utf8JsonReader(File.ReadAllBytes(inputFileName));
      EncryptedObject deserialized = JsonSerializer.Deserialize<EncryptedObject>(ref utf8Reader);
      byte[] decrypted = AESUtil.Decrypt(deserialized, password);
      File.WriteAllBytes(outputFileName, decrypted);
    }

    private static void DecryptConsoleInput(string password)
    {
      var utf8Reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(readInputFromConsole()));
      EncryptedObject deserialized = JsonSerializer.Deserialize<EncryptedObject>(ref utf8Reader);
      byte[] decrypted = AESUtil.Decrypt(deserialized, password);
      Console.WriteLine(Encoding.UTF8.GetString(decrypted));
    }

    private static void EncryptFileInput(AESUtil.EncryptionMode encryptionMode, string inputFileName, string outputFileName, string password)
    {
      EncryptedObject encryptedObject = AESUtil.Encrypt(File.ReadAllBytes(inputFileName), password, encryptionMode);
      File.WriteAllBytes(outputFileName, Encoding.UTF8.GetBytes(JsonSerializer.Serialize(encryptedObject, jsonOptions)));
    }

    private static void EncryptConsoleInput(AESUtil.EncryptionMode encryptionMode, string password)
    {
      EncryptedObject encryptedObject = AESUtil.Encrypt(readInputFromConsole(), password, encryptionMode);
      Console.WriteLine(JsonSerializer.Serialize(encryptedObject, jsonOptions));
    }

    private static void CheckCommandLineArguments(string[] args)
    {
      if (args == null || (args.Length < 3 || args.Length > 5)) printUsage();
      if (args.Length == 3 && !(args[0].ToLower().Equals("-ec") || args[0].ToLower().Equals("-dc") || args[2].ToLower().Equals("cbc") || args[2].ToLower().Equals("gcm"))) printUsage();
      if (args.Length == 4 && !(args[0].ToLower().Equals("-ef") || args[0].ToLower().Equals("-df"))) printUsage();
    }

    private static void printUsage()
    {
      Console.WriteLine(
        "\n" +
        "Usage: AESCrypto2021 -ec <password> <CBC | GCM> <input>\n" +
        "   or: AESCrypto2021 -dc <password> <input>\n" +
        "   or: AESCrypto2021 -ef <password> <CBC | GCM> <input file> <output file>\n" +
        "   or: AESCrypto2021 -df <password> <input file> <output file>\n" +
        "Examples:\n" +
        "    Encrypt input from console with password 'foo' (end input with Ctrl+Z, Enter): AESCrypto2021 -ec gcm foo\n" +
        "    Decrypt input from console with password 'foo' (end input with Ctrl+Z, Enter): AESCrypto2021 -dc foo\n" +
        "    Encrypt input from console piped in with password 'bar': echo Hello World | AESCrypto2021 -ec cbc bar\n" +
        "    Decrypt input from console piped in with password 'bar': type secret.json | AESCrypto2021 -dc bar\n" +
        "    Encrypt file 'secret.txt' with password 'jazz': AESCrypto2021 -ef cbc jazz secret.txt encrypted-secret.json\n" +
        "    Decrypt file 'encrypted-secret.json' with password 'jazz': AESCrypto2021 -df gcm jazz encrypted-secret.json secret.txt"
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
