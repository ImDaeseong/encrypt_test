using System;
using System.Security.Cryptography;
using System.Text;

namespace WindowsFormsEnc
{
    public class clsAES
    {
        private static clsAES selfInstance = null;
        public static clsAES getInstance
        {
            get
            {
                if (selfInstance == null) selfInstance = new clsAES();
                return selfInstance;
            }
        }

        public clsAES()
        {
        }

        ~clsAES()
        {
        }

        private byte[] key;
        private const int BlockSize = 16; // AES 블록 크기

        public void setKey(string keyString)
        {
            if (keyString.Length != 32)
                throw new ArgumentException("키값이 32바이트가 아닌 경우");

            key = Encoding.UTF8.GetBytes(keyString);
        }

        public string EncryptText(string plainText)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;

                aesAlg.GenerateIV(); // 랜덤 IV 생성
                byte[] iv = aesAlg.IV;

                using (ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, iv))
                {
                    byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);
                    byte[] encryptedBytes = encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);

                    byte[] resultBytes = new byte[iv.Length + encryptedBytes.Length];
                    Buffer.BlockCopy(iv, 0, resultBytes, 0, iv.Length);
                    Buffer.BlockCopy(encryptedBytes, 0, resultBytes, iv.Length, encryptedBytes.Length);

                    return Convert.ToBase64String(resultBytes);
                }
            }
        }

        public string DecryptText(string cipherText)
        {
            try
            {
                byte[] fullCipher = Convert.FromBase64String(cipherText);
                byte[] iv = new byte[BlockSize];
                byte[] cipherBytes = new byte[fullCipher.Length - BlockSize];

                Buffer.BlockCopy(fullCipher, 0, iv, 0, BlockSize);
                Buffer.BlockCopy(fullCipher, BlockSize, cipherBytes, 0, cipherBytes.Length);

                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = key;
                    aesAlg.IV = iv;
                    aesAlg.Mode = CipherMode.CBC;
                    aesAlg.Padding = PaddingMode.PKCS7;

                    using (ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
                    {
                        byte[] decryptedBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                        return Encoding.UTF8.GetString(decryptedBytes);
                    }
                }
            }
            catch (Exception e)
            {
                throw new ArgumentException($"복호화 오류: {e.Message}");
            }
        }
    }
}
