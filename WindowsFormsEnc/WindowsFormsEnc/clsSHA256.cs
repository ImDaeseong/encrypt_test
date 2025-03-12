using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace WindowsFormsEnc
{
    public class clsSHA256
    {
        private static clsSHA256 selfInstance = null;
        public static clsSHA256 getInstance
        {
            get
            {
                if (selfInstance == null) selfInstance = new clsSHA256();
                return selfInstance;
            }
        }

        public clsSHA256()
        {
        }

        ~clsSHA256()
        {
        }

        public string GetSHA256Text(string text)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(text));
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
        }

        public string GetSHA256File(string filePath, int chunkSize = 8192)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                try
                {
                    using (FileStream fileStream = File.OpenRead(filePath))
                    {
                        byte[] buffer = new byte[chunkSize];
                        int bytesRead;
                        while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            sha256.TransformBlock(buffer, 0, bytesRead, buffer, 0);
                        }
                        sha256.TransformFinalBlock(new byte[0], 0, 0);
                        return BitConverter.ToString(sha256.Hash).Replace("-", "").ToLower();
                    }
                }
                catch (IOException e)
                {
                    throw new IOException($"파일 읽기 오류: {e.Message}");
                }
            }
        }

    }
}
