using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace AESCrypto2021
{
  class AESGCM
  {
    // Get parameter sizes
    private static readonly int tagSize = AesGcm.TagByteSizes.MaxSize;

    internal static EncryptedObject Encrypt(byte[] toEncrypt, string clearTextPassword)
    {
      byte[] keySalt = AESUtil.generateSalt();
      byte[] encryptionKey = AESUtil.PBKDF2(Encoding.UTF8.GetBytes(clearTextPassword), keySalt);

      byte[] nonce = AESUtil.generateNonce();
      byte[] tag = new byte[tagSize];
      byte[] cipherText = new byte[toEncrypt.Length];

      using var aesGcm = new AesGcm(encryptionKey);
      aesGcm.Encrypt(nonce, toEncrypt, cipherText, tag);

      EncryptedObject encryptedObject = new EncryptedObject { keySalt = keySalt, nonce = nonce, tag = tag, cipherText = cipherText };

      return encryptedObject;
    }

    internal static byte[] Decrypt(EncryptedObject encryptedObject, string clearTextPassword)
    {
      byte[] encryptionKey = AESUtil.PBKDF2(Encoding.UTF8.GetBytes(clearTextPassword), encryptedObject.keySalt);
      byte[] plainText = new byte[encryptedObject.cipherText.Length];

      using var aesGcm = new AesGcm(encryptionKey);
      aesGcm.Decrypt(encryptedObject.nonce, encryptedObject.cipherText, encryptedObject.tag, plainText);
      return plainText;
    }
  }
}
