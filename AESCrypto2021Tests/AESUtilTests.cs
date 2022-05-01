using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;

namespace AESCrypto2021.Tests
{
  [TestClass()]
  public class AESUtilTests
  {
    [TestMethod()]
    public void EncryptTest()
    {
      string encrypted = AESUtil.Encrypt("Hello World", "password");
      string decrypted = Encoding.UTF8.GetString(AESUtil.Decrypt(encrypted, "password"));
      Assert.AreEqual("Hello World", decrypted);
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