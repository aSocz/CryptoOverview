using System.Security.Cryptography;

namespace EncryptionOverview.DigitalSignature
{
    public class SystemCryptographyCryptoSignature : ICryptoSigner<DSAParameters>
    {
        public (DSAParameters publicKey, DSAParameters privateKey) GetDsaKeys()
        {
            using (var csp = new DSACryptoServiceProvider(1024))
            {
                var privateKey = csp.ExportParameters(true);
                var publicKey = csp.ExportParameters(false);

                return (publicKey, privateKey);
            }
        }

        public byte[] Sign(byte[] data, DSAParameters privateKey)
        {
            using (var csp = new DSACryptoServiceProvider())
            {
                csp.ImportParameters(privateKey);

                return csp.SignData(data, HashAlgorithmName.SHA1);
            }
        }

        public bool Verify(byte[] data, byte[] signature, DSAParameters publicKey)
        {
            using (var csp = new DSACryptoServiceProvider())
            {
                csp.ImportParameters(publicKey);

                return csp.VerifyData(data, signature, HashAlgorithmName.SHA1);
            }
        }
    }
}