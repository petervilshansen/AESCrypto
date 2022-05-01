using System;
using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AESCrypto2021
{
  public static class AESUtil
  {
    public const int SALT_SIZE = 8; // size in bytes
    public const int KEY_SIZE = 32; // size in bytes
    public const int PBKDF2_ITERATIONS = 250000;

    internal static byte[] deriveEnryptionKey(string clearTextPassword, Span<byte> salt)
    {
      Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(clearTextPassword), salt.ToArray(), PBKDF2_ITERATIONS);
      byte[] encryptionKey = pbkdf2.GetBytes(KEY_SIZE);
      return encryptionKey;
    }
    public static string Encrypt(string plainText, string clearTextPassword)
    {
      return Encrypt(Encoding.UTF8.GetBytes(plainText), clearTextPassword);
    }
    public static string Encrypt(byte[] plainBytes, string clearTextPassword)
    {
      if (plainBytes == null || plainBytes.Length == 0) { throw new Exception("Plaintext cannot be null or empty."); }

      // Get parameter sizes
      int saltSize = SALT_SIZE;
      int nonceSize = AesGcm.NonceByteSizes.MaxSize;
      int tagSize = AesGcm.TagByteSizes.MaxSize;
      int cipherSize = plainBytes.Length;

      // We write everything into one big array for easier encoding
      int encryptedDataLength = 4 + saltSize + 4 + nonceSize + 4 + tagSize + cipherSize;
      Span<byte> encryptedData = encryptedDataLength < 1024
                               ? stackalloc byte[encryptedDataLength]
                               : new byte[encryptedDataLength].AsSpan();

      // Copy parameters
      BinaryPrimitives.WriteInt32LittleEndian(encryptedData.Slice(0, 4), saltSize);
      BinaryPrimitives.WriteInt32LittleEndian(encryptedData.Slice(4 + saltSize, 4), nonceSize);
      BinaryPrimitives.WriteInt32LittleEndian(encryptedData.Slice(4 + saltSize + 4 + nonceSize, 4), tagSize);

      var salt = encryptedData.Slice(4, saltSize);
      var nonce = encryptedData.Slice(4 + saltSize + 4, nonceSize);
      var tag = encryptedData.Slice(4 + saltSize + 4 + nonceSize + 4, tagSize);
      var cipherBytes = encryptedData.Slice(4 + saltSize + 4 + nonceSize + 4 + tagSize, cipherSize);

      // Generate secure nonce and salt
      RandomNumberGenerator.Fill(salt);
      RandomNumberGenerator.Fill(nonce);

      // Encrypt
      using var aes = new AesGcm(deriveEnryptionKey(clearTextPassword, salt));
      aes.Encrypt(nonce, plainBytes.AsSpan(), cipherBytes, tag);

      // Encode for transmission
      return Convert.ToBase64String(encryptedData);
    }

    public static byte[] Decrypt(string cipherText, string clearTextPassword)
    {
      // Decode
      Span<byte> encryptedData = Convert.FromBase64String(cipherText).AsSpan();

      // Extract parameter sizes
      int saltSize = BinaryPrimitives.ReadInt32LittleEndian(encryptedData.Slice(0, 4));
      int nonceSize = BinaryPrimitives.ReadInt32LittleEndian(encryptedData.Slice(4 + saltSize, 4));
      int tagSize = BinaryPrimitives.ReadInt32LittleEndian(encryptedData.Slice(4 + saltSize + 4 + nonceSize, 4));
      int cipherTextSize = encryptedData.Length - 4 - saltSize - 4 - nonceSize - 4 - tagSize;

      // Extract parameters
      var salt = encryptedData.Slice(4, saltSize);
      var nonce = encryptedData.Slice(4 + saltSize + 4, nonceSize);
      var tag = encryptedData.Slice(4 + saltSize + 4 + nonceSize + 4, tagSize);
      var cipherBytes = encryptedData.Slice(4 + saltSize + 4 + nonceSize + 4 + tagSize, cipherTextSize);

      // Decrypt
      Span<byte> plainBytes = cipherTextSize < 1024
                            ? stackalloc byte[cipherTextSize]
                            : new byte[cipherTextSize];
      using var aes = new AesGcm(deriveEnryptionKey(clearTextPassword, salt));
      aes.Decrypt(nonce, cipherBytes, tag, plainBytes);

      return plainBytes.ToArray();
    }
  }
}

