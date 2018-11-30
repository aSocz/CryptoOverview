namespace EncryptionOverview.DigitalSignature
{
    public interface ICryptoSigner<T>
    {
        (T publicKey, T privateKey) GetDsaKeys();
        byte[] Sign(byte[] data, T privateKey);
        bool Verify(byte[] data, byte[] signature, T publicKey);
    }
}