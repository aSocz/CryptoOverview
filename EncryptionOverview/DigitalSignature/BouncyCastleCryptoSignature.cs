using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;

namespace EncryptionOverview.DigitalSignature
{
    public class BouncyCastleCryptoSignature : ICryptoSigner<string>
    {
        public (string publicKey, string privateKey) GetDsaKeys()
        {
            var secureRandom = new SecureRandom();
            var parametersGenerator = new DsaParametersGenerator(new Sha1Digest());
            parametersGenerator.Init(1024, 100, secureRandom);
            var parameters = parametersGenerator.GenerateParameters();

            var g = new DsaKeyPairGenerator();
            g.Init(new DsaKeyGenerationParameters(secureRandom, parameters));
            var keyPair = g.GenerateKeyPair();

            var pkInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(keyPair.Private);
            var privateKey = Convert.ToBase64String(pkInfo.ToAsn1Object().GetDerEncoded());

            var publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public);
            var serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();
            var publicKey = Convert.ToBase64String(serializedPublicBytes);

            return (publicKey, privateKey);
        }

        public byte[] Sign(byte[] data, string privateKey)
        {
            var key = PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));

            var dsaDigestSigner = new DsaDigestSigner(new DsaSigner(), new Sha1Digest());
            dsaDigestSigner.Init(true, key);

            dsaDigestSigner.BlockUpdate(data, 0, data.Length);
            return dsaDigestSigner.GenerateSignature();
        }

        public bool Verify(byte[] data, byte[] signature, string publicKey)
        {
            var key = PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));

            var dsaDigestSigner = new DsaDigestSigner(new DsaSigner(), new Sha1Digest());
            dsaDigestSigner.Init(false, key);

            dsaDigestSigner.BlockUpdate(data, 0, data.Length);

            return dsaDigestSigner.VerifySignature(signature);
        }
    }
}