namespace EncryptionOverview.Hash
{
    public class Hashers
    {
        public IHasher SystemCryptography { get; }
        public IHasher BouncyCastle { get; }

        public Hashers()
        {
            SystemCryptography = new SystemCryptographyHash();
            BouncyCastle = new BouncyCastleHash();
        }
    }
}