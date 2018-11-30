using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace EncryptionOverview.Hash
{
    public class BouncyCastleHash : IHasher
    {
        public byte[] ComputeSha256Hash(byte[] data)
        {
            var hash = new Sha256Digest();

            return ComputeHash(data, hash);
        }

        public byte[] ComputeSha1Hash(byte[] data)
        {
            var hash = new Sha1Digest();

            return ComputeHash(data, hash);
        }

        private static byte[] ComputeHash(byte[] data, IDigest hash)
        {
            hash.BlockUpdate(data, 0, data.Length);
            var result = new byte[hash.GetDigestSize()];
            hash.DoFinal(result, 0);

            return result;
        }
    }
}