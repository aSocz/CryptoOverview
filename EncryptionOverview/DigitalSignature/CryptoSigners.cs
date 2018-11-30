using System.Security.Cryptography;

namespace EncryptionOverview.DigitalSignature
{
    public class CryptoSigners
    {
        public ICryptoSigner<DSAParameters> SystemCryptography { get; }
        public ICryptoSigner<string> BounceCastle { get; }

        public CryptoSigners()
        {
            SystemCryptography = new SystemCryptographyCryptoSignature();
            BounceCastle = new BouncyCastleCryptoSignature();
        }
    }
}