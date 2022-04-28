using System;
using System.Collections.Generic;
using System.Text;

namespace AESCrypto2021
{
  public class EncryptedBlock
  {
    public byte[] tag { get; set; }
    public byte[] cipherText { get; set; }
    public byte[] keySalt { get; set; }
    public byte[] nonce { get; set; }
  }
}
