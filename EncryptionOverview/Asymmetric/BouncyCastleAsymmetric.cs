using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;

namespace EncryptionOverview.Asymmetric
{
    public class BouncyCastleAsymmetric : IAsymmetricEncryptor<string>
    {
        public (string publicKey, string privateKey) GetRsaKeys()
        {
            var rsaKeyPairGenerator = new RsaKeyPairGenerator();
            rsaKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            var keyPair = rsaKeyPairGenerator.GenerateKeyPair();

            var pkInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            var privateKey = Convert.ToBase64String(pkInfo.ToAsn1Object().GetDerEncoded());

            var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            var serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();
            var publicKey = Convert.ToBase64String(serializedPublicBytes);

            return (publicKey, privateKey);
        }

        public byte[] EncryptRsa(byte[] plain, string publicKey)
        {
            var encryptEngine = new Pkcs1Encoding(new RsaEngine());
            var key = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));

            encryptEngine.Init(true, key);

            return encryptEngine.ProcessBlock(plain, 0, plain.Length);
        }

        public byte[] DecryptRsa(byte[] cipher, string privateKey)
        {
            var decryptEngine = new Pkcs1Encoding(new RsaEngine());
            var key = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));

            decryptEngine.Init(false, key);

            return decryptEngine.ProcessBlock(cipher, 0, cipher.Length);
        }
    }
}