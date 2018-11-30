namespace EncryptionOverview.Symmetric
{
    public class SymmetricEncryptors
    {
        public ISymmetricEncryptor SystemCryptography { get; }
        public ISymmetricEncryptor BounceCastle { get; }

        public SymmetricEncryptors()
        {
            SystemCryptography = new SystemCryptographySymmetric();
            BounceCastle = new BouncyCastleSymmetric();
        }
    }
}