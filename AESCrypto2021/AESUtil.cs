using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AESCrypto2021
{
  public static class AESUtil
  {
    public const int SALT_SIZE = 32; // size in bytes
    public const int HASH_SIZE = 32; // size in bytes
    public const int PBKDF2_ITERATIONS = 250000;
    public enum EncryptionMode { CBC, GCM };

    public static byte[] generateSalt()
    {
      byte[] salt = new byte[SALT_SIZE];
      RandomNumberGenerator.Fill(salt);
      return salt;
    }

    public static byte[] generateNonce()
    {
      byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
      RandomNumberGenerator.Fill(nonce);
      return nonce;
    }
    public static byte[] PBKDF2(byte[] clearTextPassword, byte[] salt)
    {
      Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(clearTextPassword, salt, PBKDF2_ITERATIONS);
      return pbkdf2.GetBytes(HASH_SIZE);
    }
    public static EncryptedObject Encrypt(string toEncrypt, string clearTextPassword, EncryptionMode mode)
    {
      return Encrypt(Encoding.UTF8.GetBytes(toEncrypt), clearTextPassword, mode);
    }

    public static EncryptedObject Encrypt(byte[] toEncrypt, string clearTextPassword, EncryptionMode mode)
    {
      if (toEncrypt == null || toEncrypt.Length == 0) { throw new Exception("Byte array to be encrypted cannot be null or empty."); }
      if (clearTextPassword == null || clearTextPassword.Length == 0) { throw new Exception("Encryption key cannot be null or empty."); }

      EncryptedObject encryptedObject;
      switch (mode) {
        case EncryptionMode.CBC:
          encryptedObject = AESCBC.Encrypt(toEncrypt, clearTextPassword);
          break;
        case EncryptionMode.GCM:
          encryptedObject = AESGCM.Encrypt(toEncrypt, clearTextPassword);
          break;
        default:
          throw new Exception("Unknown encryption mode: " + mode);
      }

      return encryptedObject;
    }

    public static byte[] Decrypt(EncryptedObject encryptedObject, string clearTextPassword)
    {
      byte[] decrypted;
      switch (encryptedObject.encryptionMode)
      {
        case EncryptionMode.CBC:
          decrypted = AESCBC.Decrypt(encryptedObject, clearTextPassword);
          break;
        case EncryptionMode.GCM:
          decrypted = AESGCM.Decrypt(encryptedObject, clearTextPassword);
          break;
        default:
          throw new Exception("Unknown decryption mode: " + encryptedObject.encryptionMode);
      }

      return decrypted;

    }
  }
}

