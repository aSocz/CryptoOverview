namespace EncryptionOverview.Asymmetric
{
    public interface IAsymmetricEncryptor<T>
    {
        (T publicKey, T privateKey) GetRsaKeys();
        byte[] EncryptRsa(byte[] plain, T publicKey);
        byte[] DecryptRsa(byte[] cipher, T privateKey);
    }
}