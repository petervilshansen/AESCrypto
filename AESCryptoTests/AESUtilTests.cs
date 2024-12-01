﻿using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Linq;
using Konscious.Security.Cryptography;

namespace AESCrypto.Tests
{
    [TestClass()]
    public class AESUtilTests
    {
        const string HELLO_WORLD_INPUT = "Hello, world!";
        const string UTF8_INPUT = "ăѣ𝔠ծềſģȟᎥ𝒋ǩľḿꞑȯ𝘱𝑞𝗋𝘴ȶ𝞄𝜈ψ𝒙𝘆𝚣1234567890!@#$%^&*()-_=+[{]};:'\",<.>/?~𝘈Ḇ𝖢𝕯٤ḞԍНǏ𝙅ƘԸⲘ𝙉০Ρ𝗤Ɍ𝓢ȚЦ𝒱Ѡ𝓧ƳȤѧᖯć𝗱ễ𝑓𝙜Ⴙ𝞲𝑗𝒌ļṃŉо𝞎𝒒ᵲꜱ𝙩ừ𝗏ŵ𝒙𝒚ź1234567890!@#$%^&*()-_=+[{]};:'\",<.>/?~АḂⲤ𝗗𝖤𝗙ꞠꓧȊ𝐉𝜥ꓡ𝑀𝑵Ǭ𝙿𝑄Ŗ𝑆𝒯𝖴𝘝𝘞ꓫŸ𝜡ả𝘢ƀ𝖼ḋếᵮℊ𝙝Ꭵ𝕛кιṃդⱺ𝓅𝘲𝕣𝖘ŧ𝑢ṽẉ𝘅ყž1234567890!@#$%^&*()-_=+[{]};:'\",<.>/?~Ѧ𝙱ƇᗞΣℱԍҤ١𝔍К𝓛𝓜ƝȎ𝚸𝑄Ṛ𝓢ṮṺƲᏔꓫ𝚈𝚭𝜶Ꮟçძ𝑒𝖿𝗀ḧ𝗂𝐣ҝɭḿ𝕟𝐨𝝔𝕢ṛ𝓼тú𝔳ẃ⤬𝝲𝗓1234567890!@#$%^&*()-_=+[{]};:'\",<.>/?~𝖠Β𝒞𝘋𝙴𝓕ĢȞỈ𝕵ꓗʟ𝙼ℕ০𝚸𝗤ՀꓢṰǓⅤ𝔚Ⲭ𝑌𝙕𝘢𝕤";
        const string UTF8_INPUT_WITH_HOMOGLYPHS = "𐐛𝛔гĕᵯ Ꭵ𝟈ṥ𝗎ṃ 𝜎δȱ𝐫 ậḿӭṯ, 𐐽ợ𝒏ʂễ𝙘ƭȇ𝘁ṻḕŗ ẫᏧȋ𝟈ị𝙨ɕįṇǥ ȩł𝐢ẗ. 𝔑𝒊𝙨ӏ 𝓯ṟìńցĭľḽӓ м𝐨гᖯȉ 𝐛ᶅ𝞪𝐧𝙙ıτ ḷ𝜶őŕеḝ𝘵 ẚᴦсս 𝐬ȁ𝐠Ꭵҭṱǐṣ. Ựƚŧṛ𝐢ḉꙇȩș ẝ𝚞ş𝔠𝔢 ᵵ𝞲𝗇ᴄḭ𝕕𝝊ṋ𝓽 ļ𝛔ŕẹḿ ḟḗա𝒈⍳ᶏ𝘁 ᴄǚɼṥṻᶊ 𝖋ȇ𝓾ģᶖⱥŧ ếṻ 𝒽𝖾ṋԁɾ℮𝕣𝘪𝞃. 𝑇ủ𝖗𝒑𝚒𝘀 ꞧĭ𝒹ḭ𐐽𝑢ɭҵ𝕤 ɗ𝘪𝓬𝚝ủм 𝑠ö𝗰ⅰ𝝈ŝ𝐪𝞾 𝑓𝕦š𝓬ė 𝒸ṓɱɱ𝞼𝑑о ṁâ×𝜄ṃաᶊ 𝗽èņ𝖆𝙩Ꭵḇ𝛖𝘀. 𝛮𝛖ḽȴαṃ ѵứᶅ𝓅𝞾𝘁ẚ𝔱ế е𝐟𝒇ɪҫḭ𝞽ứ𝘳 𝖋äč𝒊ꝉɪᶊỉ ƫ𝓪ꞓ𝙞ţ𝔦 ৮ⱡ𝛼𝝅ⅆĭ𝘵 ćŭЬ⍳ⱡȉạ. 𝞠𝐡åřê𝖙ɍȧ 𝐪𝓊įṩ𝗾ů𝚎 ծці ѧŧ 𝑓ěų𝘨ℹầᵵ 𝝉ō𝒓ʠμéṇ𝞃 ⱥḷ𝔦𝒒ʉėҭ 𝗽һ𝖆𝑟ḝᴛṙɑ. Ꞑůɲƈ 𝔱ȭ𝐫𝖖𝞄ḙ𝝿𝔱 ɍӏ𝙨𝒖𝙨 ɬḯɡùꞎ𝐚 𝔥𝕖ṉძŕ𝓮𝐫ᶖ𝓽 ℊ𝖗á𝗏𝚤ḍ𝗮 ⲣɽ𝜶ℯ𝚜ℯᵰť Գǘḯ𝐬.";

        [TestMethod()]
        public void EncryptDecryptTestTextInput()
        {
            AesRecord aesRecord = AESUtil.Encrypt(Encoding.UTF8.GetBytes(HELLO_WORLD_INPUT));
            string decrypted = Encoding.UTF8.GetString(AESUtil.Decrypt(Convert.ToBase64String(aesRecord.payload), aesRecord.password));
            Assert.AreEqual(HELLO_WORLD_INPUT, decrypted);
        }

        [TestMethod()]
        public void EncryptDecryptTestUTF8Input()
        {
            // https://stackoverflow.com/questions/1319022/really-good-bad-utf-8-example-test-data
            AesRecord aesRecord = AESUtil.Encrypt(Encoding.UTF8.GetBytes(UTF8_INPUT));
            string decrypted = Encoding.UTF8.GetString(AESUtil.Decrypt(Convert.ToBase64String(aesRecord.payload), aesRecord.password));
            Assert.AreEqual(UTF8_INPUT, decrypted);
        }

        [TestMethod()]
        public void EncryptDecryptTestUTF8InputLoremIpsumHomoglyphs()
        {
            // https://jeff.cis.cabrillo.edu/tools/homoglyphs
            AesRecord aesRecord = AESUtil.Encrypt(Encoding.UTF8.GetBytes(UTF8_INPUT_WITH_HOMOGLYPHS));
            string decrypted = Encoding.UTF8.GetString(AESUtil.Decrypt(Convert.ToBase64String(aesRecord.payload), aesRecord.password));
            Assert.AreEqual(UTF8_INPUT_WITH_HOMOGLYPHS, decrypted);
        }

        [TestMethod()]
        public void EncryptDecryptTestRandomBinaryInput()
        {
            byte[] random = new byte[1024];
            RandomNumberGenerator.Fill(random);
            AesRecord aesRecord = AESUtil.Encrypt(random);
            byte[] decrypted = AESUtil.Decrypt(Convert.ToBase64String(aesRecord.payload), aesRecord.password);
            Assert.AreEqual(Convert.ToBase64String(random), Convert.ToBase64String(decrypted));
        }

        [TestMethod()]
        public void EncryptTestFail()
        {
            AesRecord aesRecord = AESUtil.Encrypt(Encoding.UTF8.GetBytes(HELLO_WORLD_INPUT));
            try
            {
                string decrypted = Encoding.UTF8.GetString(AESUtil.Decrypt(Convert.ToBase64String(aesRecord.payload), "wrong_password"));
            }
            catch (Exception ex)
            {
                Assert.IsTrue(ex.Message.StartsWith("Error during decryption:"));
                return;
            }
            Assert.Fail();
        }

        [TestMethod()]
        public void EncryptTestUsingBouncyCastleAesGcm()
        {
            // 0. Define an input string to be encrypted
            // 1. Encrypt the input string using AESUtil.cs
            // 2. Encrypt the same input string using BouncyCastle
            // 3. Assert that output from step 1 == output from step 2
            // 4. Assert that BouncyCastle can successfully decrypt output from step 1

            // -----------------------------------------------------------------------

            // Step 0

            const string plainText = UTF8_INPUT;

            // Step 1. Encrypt the input string using AESUtil.cs

            AesRecord aesRecord = AESUtil.Encrypt(Encoding.UTF8.GetBytes(plainText));

            // Step 2. Encrypt the same input string using BouncyCastle

            var argon2 = new Argon2id(Encoding.UTF8.GetBytes(aesRecord.password))
            {
                Salt = aesRecord.salt,
                DegreeOfParallelism = Argon2.DEGREE_OF_PARALLELLISM, // number of threads to use
                MemorySize = Argon2.MEMORY_TO_USE_KILOBYTES, // 1 GB
                Iterations = Argon2.NUMBER_OF_ITERATIONS
            };

            byte[] key = argon2.GetBytes(32); // 32 bytes hash
            byte[] nonce = aesRecord.nonce;  // 96-bit nonce

            GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
            AeadParameters parameters = new AeadParameters(new KeyParameter(key), 128, nonce);
            cipher.Init(true, parameters);

            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] ciphertextBytes = new byte[cipher.GetOutputSize(plaintextBytes.Length)];
            int len = cipher.ProcessBytes(plaintextBytes, 0, plaintextBytes.Length, ciphertextBytes, 0);
            cipher.DoFinal(ciphertextBytes, len);

            byte[] ciphertext = ciphertextBytes.Take(ciphertextBytes.Length - 16).ToArray();
            byte[] tag = ciphertextBytes.Skip(ciphertextBytes.Length - 16).Take(16).ToArray();
            Console.WriteLine($"Ciphertext: {Convert.ToBase64String(ciphertext)}");
            Console.WriteLine($"Tag: {Convert.ToBase64String(tag)}");

            // 3. Assert that output from step 1 == output from step 2

            Assert.IsTrue(aesRecord.cipherText.SequenceEqual(ciphertext));
            Assert.IsTrue(aesRecord.tag.SequenceEqual(tag));

            // 4. Assert that BouncyCastle can successfully decrypt output from step 1

            cipher = new GcmBlockCipher(new AesEngine());
            parameters = new AeadParameters(new KeyParameter(key), 128, aesRecord.nonce);
            cipher.Init(false, parameters);

            // BounyCastle ciphertext includes the GCM tag, AESUTil.cs splits these into two, so we
            // concatenate them here for BouncyCastle.
            byte[] cipherTextAndTag = aesRecord.cipherText.Concat(aesRecord.tag).ToArray();
            plaintextBytes = new byte[cipher.GetOutputSize(cipherTextAndTag.Length)];
            len = cipher.ProcessBytes(cipherTextAndTag, 0, cipherTextAndTag.Length, plaintextBytes, 0);
            cipher.DoFinal(plaintextBytes, len);
            Assert.IsTrue(Encoding.UTF8.GetString(plaintextBytes).TrimEnd('\0').SequenceEqual(plainText));
        }
    }
}