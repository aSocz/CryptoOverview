using System.Security.Cryptography;

namespace EncryptionOverview.Asymmetric
{
    public class SystemCryptographyAsymmetric : IAsymmetricEncryptor<RSAParameters>
    {
        public (RSAParameters publicKey, RSAParameters privateKey) GetRsaKeys()
        {
            using (var csp = new RSACryptoServiceProvider(2048))
            {
                var privateKey = csp.ExportParameters(true);
                var publicKey = csp.ExportParameters(false);

                return (publicKey, privateKey);
            }
        }

        public byte[] EncryptRsa(byte[] plain, RSAParameters publicKey)
        {
            using (var csp = new RSACryptoServiceProvider())
            {
                csp.ImportParameters(publicKey);

                return csp.Encrypt(plain, false);
            }
        }

        public byte[] DecryptRsa(byte[] cipher, RSAParameters privateKey)
        {
            using (var csp = new RSACryptoServiceProvider())
            {
                csp.ImportParameters(privateKey);

                return csp.Decrypt(cipher, false);
            }
        }

    }
}