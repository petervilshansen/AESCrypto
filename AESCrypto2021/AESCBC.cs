using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AESCrypto2021
{
  class AESCBC
  {
    internal static EncryptedObject Encrypt(byte[] toEncrypt, string clearTextPassword)
    {
      byte[] saltEnc = AESUtil.generateSalt();
      byte[] encryptionKey = AESUtil.PBKDF2(Encoding.UTF8.GetBytes(clearTextPassword), saltEnc);
      byte[] saltMac = AESUtil.generateSalt();
      byte[] macKey = AESUtil.PBKDF2(Encoding.UTF8.GetBytes(clearTextPassword), saltMac);

      using var aes = new AesManaged() { KeySize = 256, Key = encryptionKey, Padding = PaddingMode.PKCS7, Mode = CipherMode.CBC };

      EncryptedObject encryptedObject;
      using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
      using (var cipherTextStream = new MemoryStream())
      {
        using (var encrypterStream = new CryptoStream(cipherTextStream, encryptor, CryptoStreamMode.Write))
        using (var binaryWriter = new BinaryWriter(encrypterStream))
        {
          binaryWriter.Write(toEncrypt);
        }

        HMACSHA256 hMACSHA256 = new HMACSHA256(macKey);
        byte[] mac = hMACSHA256.ComputeHash(cipherTextStream.ToArray());
        encryptedObject = new EncryptedObject { iv = aes.IV, saltEnc = saltEnc, saltMac = saltMac, cipherText = cipherTextStream.ToArray(), mac = mac, encryptionMode = AESUtil.EncryptionMode.CBC };
      }
      return encryptedObject;
    }

    internal static byte[] Decrypt(EncryptedObject encryptedObject, string clearTextPassword)
    {
      byte[] decryptionKey = AESUtil.PBKDF2(Encoding.UTF8.GetBytes(clearTextPassword), encryptedObject.saltEnc);
      byte[] macKey = AESUtil.PBKDF2(Encoding.UTF8.GetBytes(clearTextPassword), encryptedObject.saltMac);

      HMACSHA256 hMACSHA256 = new HMACSHA256(macKey);
      byte[] mac = hMACSHA256.ComputeHash(encryptedObject.cipherText);
      if (!Enumerable.SequenceEqual(mac, encryptedObject.mac))
      {
        throw new Exception("HMAC does not match! " + Convert.ToBase64String(mac) + ", " + Convert.ToBase64String(encryptedObject.mac));
      }

      using var aes = new AesManaged() { KeySize = 256, Key = decryptionKey, Padding = PaddingMode.PKCS7, Mode = CipherMode.CBC, IV = encryptedObject.iv };
      using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
      using (var plaintextStream = new MemoryStream())
      {
        using (var decrypterStream = new CryptoStream(plaintextStream, decryptor, CryptoStreamMode.Write))
        using (var binaryWriter = new BinaryWriter(decrypterStream))
        {
          binaryWriter.Write(encryptedObject.cipherText);
        }

        return plaintextStream.ToArray();
      }
    }
  }
}
