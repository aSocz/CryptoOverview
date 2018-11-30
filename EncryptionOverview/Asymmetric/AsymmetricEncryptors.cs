using System.Security.Cryptography;

namespace EncryptionOverview.Asymmetric
{
    public class AsymmetricEncryptors
    {
        public IAsymmetricEncryptor<RSAParameters> SystemCryptography { get; }
        public IAsymmetricEncryptor<string> BouncyCastle { get; }

        public AsymmetricEncryptors()
        {
            SystemCryptography = new SystemCryptographyAsymmetric();
            BouncyCastle = new BouncyCastleAsymmetric();
        }
    }
}