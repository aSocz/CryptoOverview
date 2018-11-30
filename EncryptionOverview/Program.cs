using EncryptionOverview.Asymmetric;
using EncryptionOverview.DigitalSignature;
using EncryptionOverview.Hash;
using EncryptionOverview.Symmetric;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionOverview
{
    internal class Program
    {
        public const string Password = "E>6Qq-ae,!(<,cxP";

        private static async Task Main(string[] args)
        {
            Console.WriteLine("Application is loading... Please wait");

            var filePath = GetFilePath();
            var message = await File.ReadAllTextAsync(filePath);

            CompareSymmetric(message);
            CompareAsymmetric(message);
            CompareHash(message);
            CompareCryptoSigners(message);
        }

        private static void CompareSymmetric(string message)
        {
            var symmetricEncryptors = new SymmetricEncryptors();

            var messageRaw = Encoding.UTF8.GetBytes(message);

            var rijndaelEncryptedRaw = symmetricEncryptors.SystemCryptography.EncryptRijndael(messageRaw, Password);
            var rijndaelDecryptedRaw =
                symmetricEncryptors.SystemCryptography.DecryptRijndael(rijndaelEncryptedRaw, Password);

            var rijndaelDecrypted = Encoding.UTF8.GetString(rijndaelDecryptedRaw);

            var tripleDesEncryptedRaw = symmetricEncryptors.SystemCryptography.EncryptTripleDes(messageRaw, Password);
            var tripleDesDecryptedRaw =
                symmetricEncryptors.SystemCryptography.DecryptTripleDes(tripleDesEncryptedRaw, Password);

            var tripleDesDecrypted = Encoding.UTF8.GetString(tripleDesDecryptedRaw);

            Console.WriteLine("\n");
            Console.WriteLine($"System.Security.Cryptography: Original message: {message}");
            Console.WriteLine($"System.Security.Cryptography: Rijndael decrypted message: {rijndaelDecrypted}");
            Console.WriteLine($"System.Security.Cryptography: Triple DES decrypted message: {tripleDesDecrypted}");

            var areSame = AreSame(message, rijndaelDecrypted, tripleDesDecrypted);

            Console.WriteLine($"System.Security.Cryptography: Are same? {areSame}");
            Console.WriteLine("\n\n");

            rijndaelEncryptedRaw = symmetricEncryptors.BounceCastle.EncryptRijndael(messageRaw, Password);
            rijndaelDecryptedRaw = symmetricEncryptors.BounceCastle.DecryptRijndael(rijndaelEncryptedRaw, Password);

            rijndaelDecrypted = Encoding.UTF8.GetString(rijndaelDecryptedRaw);

            tripleDesEncryptedRaw = symmetricEncryptors.BounceCastle.EncryptTripleDes(messageRaw, Password);
            tripleDesDecryptedRaw = symmetricEncryptors.BounceCastle.DecryptTripleDes(tripleDesEncryptedRaw, Password);

            tripleDesDecrypted = Encoding.UTF8.GetString(tripleDesDecryptedRaw);

            Console.WriteLine($"Bounce Castle: Original message: {message}");
            Console.WriteLine($"Bounce Castle: Rijndael decrypted message: {rijndaelDecrypted}");
            Console.WriteLine($"Bounce Castle: Triple DES decrypted message: {tripleDesDecrypted}");

            areSame = AreSame(message, rijndaelDecrypted, tripleDesDecrypted);

            Console.WriteLine($"Bounce Castle: Are same? {areSame}");
            Console.WriteLine("\n\n");
            Console.WriteLine("Press any key to continue");

            Console.ReadKey();
        }

        private static void CompareAsymmetric(string message)
        {
            var asymmetricEncryptors = new AsymmetricEncryptors();

            var messageRaw = Encoding.UTF8.GetBytes(message);

            var (publicKey, privateKey) = asymmetricEncryptors.SystemCryptography.GetRsaKeys();

            var rsaEncryptedRaw = asymmetricEncryptors.SystemCryptography.EncryptRsa(messageRaw, publicKey);
            var rsaDecryptedRaw = asymmetricEncryptors.SystemCryptography.DecryptRsa(rsaEncryptedRaw, privateKey);

            var rsaDecrypted = Encoding.UTF8.GetString(rsaDecryptedRaw);

            Console.WriteLine($"System.Security.Cryptography: Original message: {message}");
            Console.WriteLine($"System.Security.Cryptography: RSA decrypted message: {rsaDecrypted}");

            var areSame = string.Equals(message, rsaDecrypted);

            Console.WriteLine($"System.Security.Cryptography: Are same? {areSame}");
            Console.WriteLine("\n\n");

            var (publicKeyBouncy, privateKeyBouncy) = asymmetricEncryptors.BouncyCastle.GetRsaKeys();

            rsaEncryptedRaw = asymmetricEncryptors.BouncyCastle.EncryptRsa(messageRaw, publicKeyBouncy);
            rsaDecryptedRaw = asymmetricEncryptors.BouncyCastle.DecryptRsa(rsaEncryptedRaw, privateKeyBouncy);

            rsaDecrypted = Encoding.UTF8.GetString(rsaDecryptedRaw);

            Console.WriteLine($"BouncyCastle: Original message: {message}");
            Console.WriteLine($"BouncyCastle: RSA decrypted message: {rsaDecrypted}");

            areSame = string.Equals(message, rsaDecrypted);

            Console.WriteLine($"BouncyCastle: Are same? {areSame}");
            Console.WriteLine("\n\n");
            Console.WriteLine("Press any key to continue");

            Console.ReadKey();
        }

        private static void CompareHash(string message)
        {
            var hashers = new Hashers();

            var messageRaw = Encoding.UTF8.GetBytes(message);

            var sha256Hash = hashers.SystemCryptography.ComputeSha256Hash(messageRaw);
            var sha1Hash = hashers.SystemCryptography.ComputeSha1Hash(messageRaw);

            Console.WriteLine($"System.Security.Cryptography: SHA256 hash: {BitConverter.ToString(sha256Hash)}");
            Console.WriteLine($"System.Security.Cryptography: SHA1 hash: {BitConverter.ToString(sha1Hash)}");

            Console.WriteLine("\n\n");

            sha256Hash = hashers.BouncyCastle.ComputeSha256Hash(messageRaw);
            sha1Hash = hashers.BouncyCastle.ComputeSha1Hash(messageRaw);

            Console.WriteLine($"BouncyCastle: SHA256 hash: {BitConverter.ToString(sha256Hash)}");
            Console.WriteLine($"BouncyCastle: SHA1 hash: {BitConverter.ToString(sha1Hash)}");

            Console.WriteLine("\n\n");
            Console.WriteLine("Press any key to continue");

            Console.ReadKey();
        }

        private static void CompareCryptoSigners(string message)
        {
            var cryptoSigners = new CryptoSigners();

            var messageRaw = Encoding.UTF8.GetBytes(message);

            var (publicKey, privateKey) = cryptoSigners.SystemCryptography.GetDsaKeys();
            var signature = cryptoSigners.SystemCryptography.Sign(messageRaw, privateKey);
            var verification = cryptoSigners.SystemCryptography.Verify(messageRaw, signature, publicKey);

            var verificationResult = verification ? "Correct" : "Incorrect";

            Console.WriteLine($"System.Security.Cryptography: Signature: {BitConverter.ToString(signature)}");
            Console.WriteLine($"System.Security.Cryptography: Verification result: {verificationResult}");

            Console.WriteLine("\n\n");

            var (publicKeyBouncy, privateKeyBouncy) = cryptoSigners.BounceCastle.GetDsaKeys();
            signature = cryptoSigners.BounceCastle.Sign(messageRaw, privateKeyBouncy);
            verification = cryptoSigners.BounceCastle.Verify(messageRaw, signature, publicKeyBouncy);

            verificationResult = verification ? "Correct" : "Incorrect";

            Console.WriteLine($"BouncyCastle: Signature: {BitConverter.ToString(signature)}");
            Console.WriteLine($"BouncyCastle: Verification result: {verificationResult}");

            Console.WriteLine("\n\n");
            Console.WriteLine("Press any key to continue");

            Console.ReadKey();
        }

        private static bool AreSame(string originalMessage, string firstMessage, string secondMessage)
        {
            return string.Equals(originalMessage, firstMessage)
                && string.Equals(originalMessage, secondMessage);
        }

        private static string GetFilePath()
        {
            string filePath;

            do
            {
                Console.WriteLine("Please give file path");
                filePath = Console.ReadLine();
            } while (!File.Exists(filePath));

            return filePath;
        }
    }
}