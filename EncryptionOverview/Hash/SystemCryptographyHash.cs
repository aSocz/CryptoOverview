using System.Security.Cryptography;

namespace EncryptionOverview.Hash
{
    public class SystemCryptographyHash : IHasher
    {
        public byte[] ComputeSha256Hash(byte[] data)
        {
            using (var sha256Hash = SHA256.Create())
            {
                return sha256Hash.ComputeHash(data);
            }
        }

        public byte[] ComputeSha1Hash(byte[] data)
        {
            using (var sha1Hash = SHA1.Create())
            {
                return sha1Hash.ComputeHash(data);
            }
        }
    }
}