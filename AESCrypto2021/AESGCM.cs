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
      byte[] saltEnc = AESUtil.generateSalt();
      byte[] encryptionKey = AESUtil.PBKDF2(Encoding.UTF8.GetBytes(clearTextPassword), saltEnc);

      byte[] nonce = AESUtil.generateNonce();
      byte[] tag = new byte[tagSize];
      byte[] cipherText = new byte[toEncrypt.Length];

      RandomNumberGenerator.Fill(nonce);

      using var aesGcm = new AesGcm(encryptionKey);
      aesGcm.Encrypt(nonce, toEncrypt, cipherText, tag);

      EncryptedObject encryptedObject = new EncryptedObject { saltEnc = saltEnc, nonce = nonce, tag = tag, cipherText = cipherText, encryptionMode = AESUtil.EncryptionMode.GCM };

      return encryptedObject;
    }

    internal static byte[] Decrypt(EncryptedObject encryptedObject, string clearTextPassword)
    {
      byte[] encryptionKey = AESUtil.PBKDF2(Encoding.UTF8.GetBytes(clearTextPassword), encryptedObject.saltEnc);
      byte[] plainText = new byte[encryptedObject.cipherText.Length];

      using var aesGcm = new AesGcm(encryptionKey);
      aesGcm.Decrypt(encryptedObject.nonce, encryptedObject.cipherText, encryptedObject.tag, plainText);
      return plainText;
    }
  }
}
