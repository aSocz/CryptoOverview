namespace EncryptionOverview.Symmetric
{
    public interface ISymmetricEncryptor
    {
        byte[] EncryptRijndael(byte[] plain, string password);

        byte[] DecryptRijndael(byte[] cipher, string password);

        byte[] EncryptTripleDes(byte[] plain, string password);

        byte[] DecryptTripleDes(byte[] cipher, string password);
    }
}