using System;
using System.Text;

namespace AESCrypto
{
  class UTF8Dump
  {
    private static UTF8Encoding utf8 = new UTF8Encoding();

    public static void printHex(string utf8String)
    {
      Byte[] encodedBytes = utf8.GetBytes(utf8String);
      Console.WriteLine();
      Console.WriteLine("Input string:");
      Console.WriteLine(utf8String);
      Console.WriteLine("Hex encoded:");
      for (int ctr = 0; ctr < encodedBytes.Length; ctr++)
      {
        Console.Write("{0:X2} ", encodedBytes[ctr]);
        if ((ctr + 1) % 25 == 0)
          Console.WriteLine();
      }
      Console.WriteLine();
    }
  }
}
