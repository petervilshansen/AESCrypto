using System;
using System.Collections.Generic;
using System.Text;

namespace AESCrypto2021
{
  public class EncryptedObject
  {
    public byte[] iv { get; set; }
    public byte[] saltEnc { get; set; }
    public byte[] saltMac { get; set; }
    public byte[] cipherText { get; set; }
    public byte[] mac { get; set; }
    public byte[] tag { get; set; }
    public byte[] nonce { get; set; }
    public AESUtil.EncryptionMode encryptionMode { get; set; }
  }
}
