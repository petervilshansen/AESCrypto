using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography;
using System.Text;

namespace AESCrypto2021.Tests
{
  [TestClass()]
  public class AESUtilTests
  {
    [TestMethod()]
    public void EncryptTestTextInput()
    {
      string encrypted = AESUtil.Encrypt("Hello World", "password");
      string decrypted = Encoding.UTF8.GetString(AESUtil.Decrypt(encrypted, "password"));
      Assert.AreEqual("Hello World", decrypted);
    }

    [TestMethod()]
    public void EncryptTestBinaryInput()
    {
      byte[] random = new byte[1024];
      RandomNumberGenerator.Fill(random);
      string encrypted = AESUtil.Encrypt(random, "password");
      byte[] decrypted = AESUtil.Decrypt(encrypted, "password");
      Assert.AreEqual(System.Convert.ToBase64String(random), System.Convert.ToBase64String(decrypted));
    }

    [TestMethod()]
    public void EncryptTestFail()
    {
      string encrypted = AESUtil.Encrypt("Hello World", "password");
      try
      {
        string decrypted = Encoding.UTF8.GetString(AESUtil.Decrypt(encrypted, "wrong"));
      } catch (Exception ex)
      {
        Assert.IsTrue(ex.Message.StartsWith("Error during decryption:"));
        return;
      }
      Assert.Fail();
    }
  }
}