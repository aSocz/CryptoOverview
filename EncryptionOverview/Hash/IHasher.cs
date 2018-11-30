namespace EncryptionOverview.Hash
{
    public interface IHasher
    {
        byte[] ComputeSha256Hash(byte[] data);
        byte[] ComputeSha1Hash(byte[] data);
    }
}