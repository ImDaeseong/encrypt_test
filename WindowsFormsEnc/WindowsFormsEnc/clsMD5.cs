using System;
using System.Text;
using System.IO;
using System.Security.Cryptography;

namespace WindowsFormsEnc
{
    public class clsMD5
    {
        private static clsMD5 selfInstance = null;
        public static clsMD5 getInstance
        {
            get
            {
                if (selfInstance == null) selfInstance = new clsMD5();
                return selfInstance;
            }
        }

        public clsMD5()
        {
        }

        ~clsMD5()
        {
        }

        public string GetMD5Text(string text)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(text);
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
        }

        public string GetMD5File(string filePath, int chunkSize = 8192)
        {
            using (MD5 md5 = MD5.Create())
            {
                try
                {
                    using (FileStream stream = File.OpenRead(filePath))
                    {
                        byte[] buffer = new byte[chunkSize];
                        int bytesRead;
                        while ((bytesRead = stream.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            md5.TransformBlock(buffer, 0, bytesRead, buffer, 0);
                        }
                        md5.TransformFinalBlock(new byte[0], 0, 0);
                        return BitConverter.ToString(md5.Hash).Replace("-", "").ToLower();
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
