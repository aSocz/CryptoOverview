using System.IO;
using System.Security.Cryptography;

namespace EncryptionOverview.Symmetric
{
    public class SystemCryptographySymmetric : ISymmetricEncryptor
    {
        private static readonly byte[] SALT =
        {
            0x26, 0xdc, 0xff, 0x00, 0xad, 0xed, 0x7a, 0xee, 0xc5, 0xfe, 0x07, 0xaf, 0x4d, 0x08, 0x22, 0x3c
        };

        public byte[] EncryptRijndael(byte[] plain, string password)
        {
            using (var rijndael = GetRijndael(password))
            {
                return GetCipher(plain, rijndael);
            }
        }

        public byte[] DecryptRijndael(byte[] cipher, string password)
        {
            using (var rijndael = GetRijndael(password))
            {
                return GetResult(cipher, rijndael);
            }
        }

        public byte[] EncryptTripleDes(byte[] plain, string password)
        {
            using (var tripleDes = GetTripleDes(password))
            {
                return GetCipher(plain, tripleDes);
            }
        }

        public byte[] DecryptTripleDes(byte[] cipher, string password)
        {
            using (var tripleDes = GetTripleDes(password))
            {
                return GetResult(cipher, tripleDes);
            }
        }

        private static RijndaelManaged GetRijndael(string password)
        {
            var rijndael = new RijndaelManaged();
            var pdb = GetDeriveBytes(password);

            rijndael.Key = pdb.GetBytes(32);
            rijndael.IV = pdb.GetBytes(16);

            return rijndael;
        }

        private static TripleDESCryptoServiceProvider GetTripleDes(string password)
        {
            var tripleDes = new TripleDESCryptoServiceProvider();
            var pdb = GetDeriveBytes(password);

            tripleDes.Key = pdb.GetBytes(24);
            tripleDes.IV = pdb.GetBytes(8);

            return tripleDes;
        }

        private static byte[] GetResult(byte[] cipher, SymmetricAlgorithm algorithm)
        {
            using (var memoryStream = new MemoryStream())
            using (var cryptoStream = new CryptoStream(memoryStream, algorithm.CreateDecryptor(), CryptoStreamMode.Write))
            {
                cryptoStream.Write(cipher, 0, cipher.Length);
                cryptoStream.Close();

                return memoryStream.ToArray();
            }
        }

        private static byte[] GetCipher(byte[] plainText, SymmetricAlgorithm algorithm)
        {
            using (var memoryStream = new MemoryStream())
            using (var cryptoStream = new CryptoStream(memoryStream, algorithm.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cryptoStream.Write(plainText, 0, plainText.Length);
                cryptoStream.Close();

                return memoryStream.ToArray();
            }
        }

        private static Rfc2898DeriveBytes GetDeriveBytes(string password) => new Rfc2898DeriveBytes(password, SALT);
    }
}