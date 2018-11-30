using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using System;

namespace EncryptionOverview.Symmetric
{
    public class BouncyCastleSymmetric : ISymmetricEncryptor
    {
        private const int rijndaelKeyBitSize = 32 * 8;
        private const int tripleDesKeyBitSize = 16 * 8;

        private static readonly byte[] SALT =
        {
            0x26, 0xdc, 0xff, 0x00, 0xad, 0xed, 0x7a, 0xee, 0xc5, 0xfe, 0x07, 0xaf, 0x4d, 0x08, 0x22, 0x3c
        };

        public byte[] EncryptRijndael(byte[] plain, string password)
        {
            var engine = new RijndaelEngine(rijndaelKeyBitSize);
            var encryptorParameters = GenerateParameters(password, rijndaelKeyBitSize);

            return Encrypt(plain, engine, encryptorParameters);
        }

        public byte[] DecryptRijndael(byte[] cipher, string password)
        {
            var engine = new RijndaelEngine(rijndaelKeyBitSize);
            var decryptorParameters = GenerateParameters(password, rijndaelKeyBitSize);

            return Decrypt(cipher, engine, decryptorParameters);
        }

        public byte[] EncryptTripleDes(byte[] plain, string password)
        {
            var engine = new DesEdeEngine();
            var encryptorParameters = GenerateParameters(password, tripleDesKeyBitSize, engine.GetBlockSize() * 8);

            return Encrypt(plain, engine, encryptorParameters);
        }

        public byte[] DecryptTripleDes(byte[] cipher, string password)
        {
            var engine = new DesEdeEngine();
            var decryptorParameters = GenerateParameters(password, tripleDesKeyBitSize, engine.GetBlockSize() * 8);

            return Decrypt(cipher, engine, decryptorParameters);
        }

        private static byte[] Encrypt(byte[] plain, IBlockCipher engine, ICipherParameters encryptorParameters)
        {
            var encryptor = new PaddedBufferedBlockCipher(new CbcBlockCipher(engine));
            encryptor.Init(true, encryptorParameters);

            var size = encryptor.GetOutputSize(plain.Length);
            var result = new byte[size];

            var olen = encryptor.ProcessBytes(plain, 0, plain.Length, result, 0);
            olen += encryptor.DoFinal(result, olen);

            if (olen < size)
            {
                var tmp = new byte[olen];
                Array.Copy(result, 0, tmp, 0, olen);
                result = tmp;
            }

            return result;
        }

        private static byte[] Decrypt(byte[] cipher, IBlockCipher engine, ICipherParameters decryptorParameters)
        {
            var decryptor = new PaddedBufferedBlockCipher(new CbcBlockCipher(engine));
            decryptor.Init(false, decryptorParameters);

            var size = decryptor.GetOutputSize(cipher.Length);
            var result = new byte[size];

            var olen = decryptor.ProcessBytes(cipher, 0, cipher.Length, result, 0);
            olen += decryptor.DoFinal(result, olen);

            if (olen < size)
            {
                var tmp = new byte[olen];
                Array.Copy(result, 0, tmp, 0, olen);
                result = tmp;
            }

            return result;
        }

        private ICipherParameters GenerateParameters(string password, int keySize, int? ivSize = null)
        {
            return GenerateKey(password, keySize, ivSize);
        }

        private static ICipherParameters GenerateKey(string password, int keySize, int? ivSize = null)
        {
            var generator = new Pkcs5S2ParametersGenerator();
            generator.Init(PbeParametersGenerator.Pkcs5PasswordToUtf8Bytes(password.ToCharArray()), SALT, 1000);

            return generator.GenerateDerivedParameters("AES", keySize, ivSize ?? keySize);
        }
    }
}