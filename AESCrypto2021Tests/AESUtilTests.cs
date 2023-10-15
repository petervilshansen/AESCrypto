using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace AESCrypto2021.Tests
{
    [TestClass()]
    public class AESUtilTests
    {
        [TestMethod()]
        public void EncryptDecryptTestTextInput()
        {
            (string cipherText, string password) = AESUtil.Encrypt(Encoding.UTF8.GetBytes("Hello World"));
            string decrypted = Encoding.UTF8.GetString(AESUtil.Decrypt(cipherText, password));
            Assert.AreEqual("Hello World", decrypted);
        }

        [TestMethod()]
        public void EncryptDecryptTestBinaryInput()
        {
            byte[] random = new byte[1024];
            RandomNumberGenerator.Fill(random);
            (string cipherText, string password) = AESUtil.Encrypt(random);
            byte[] decrypted = AESUtil.Decrypt(cipherText, password);
            Assert.AreEqual(System.Convert.ToBase64String(random), System.Convert.ToBase64String(decrypted));
        }

        [TestMethod()]
        public void EncryptTestFail()
        {
            (string cipherText, string password) = AESUtil.Encrypt(Encoding.UTF8.GetBytes("Hello World"));
            try
            {
                string decrypted = Encoding.UTF8.GetString(AESUtil.Decrypt(cipherText, "wrong"));
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex.Message.StartsWith("Error during decryption:"));
                return;
            }
            Assert.Fail();
        }
    }
}