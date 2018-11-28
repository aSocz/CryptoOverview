using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace EncryptionOverview
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var password = "E>6Qq-ae,!(<,cxP";
            Console.WriteLine("Application is loading... Please wait");
            var systemCrypto = new SystemCryptography();

            var filePath = GetFilePath();
            var message = await File.ReadAllTextAsync(filePath);

            var messageRaw = Encoding.UTF8.GetBytes(message);

            var rijndaelEncryptedMessageRaw = systemCrypto.EncryptRijndael(messageRaw, password);
            var rijndaelDecryptedMessageRaw = systemCrypto.DecryptRijndael(rijndaelEncryptedMessageRaw, password);
            var rijndaelDecryptedMessage = Encoding.UTF8.GetString(rijndaelDecryptedMessageRaw);

            var tripleDesEncryptedMessageRaw = systemCrypto.EncryptTripleDes(messageRaw, password);
            var tripleDesDecryptedMessageRaw = systemCrypto.DecryptTripleDes(tripleDesEncryptedMessageRaw, password);
            var tripleDesDecryptedMessage = Encoding.UTF8.GetString(tripleDesDecryptedMessageRaw);

            Console.WriteLine($"Original message: {message}");
            Console.WriteLine($"Rijndael decrypted message: {rijndaelDecryptedMessage}");
            Console.WriteLine($"Triple DES decrypted message: {tripleDesDecryptedMessage}");

            var areSame = AreSame(message, rijndaelDecryptedMessage, tripleDesDecryptedMessage);

            Console.WriteLine($"Are same? {areSame}");

            Console.ReadKey();
        }

        private static bool AreSame(string message, string rijndaelDecryptedMessage, string tripleDesDecryptedMessage)
        {
            return string.Equals(message, rijndaelDecryptedMessage)
                && string.Equals(message, tripleDesDecryptedMessage);
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
