using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;

namespace WindowsFormsEnc
{
    public partial class Form1 : Form
    {
        clsMD5 objmd5 = clsMD5.getInstance;
        clsSHA256 objsha256 = clsSHA256.getInstance;
        clsAES objaes = clsAES.getInstance;

        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            f1();
            f2();
            f3();
        }

        //MD5
        private void f1()
        {
            //문자열
            string strText = "문자열md5";
            string strHash = objmd5.GetMD5Text(strText);
            Console.WriteLine($"MD5: \"{strText}\" - {strHash} - {strHash.Length}");

            //파일
            string strFolderPath = @"E:\Battle.net";
            if (!Directory.Exists(strFolderPath))
                return;

            string[] files = Directory.GetFiles(strFolderPath);
            if (files.Length == 0)
                return;
                
            foreach (string filePath in files)
            {
                try
                {
                    string strFileHash = objmd5.GetMD5File(filePath);
                    Console.WriteLine($"md5: {filePath} - {strFileHash} - {strFileHash.Length}");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"오류 발생 (파일: {Path.GetFileName(filePath)}): {e.Message}");
                }
            }
        }

        //SHA256
        private void f2()
        {
            //문자열
            string strText = "문자열sha256";
            string strHash = objsha256.GetSHA256Text(strText);
            Console.WriteLine($"f'sha256: \"{strText}\" - {strHash} - {strHash.Length}");

            //파일
            string strFolderPath = @"E:\Battle.net";
            if (!Directory.Exists(strFolderPath))
                return;

            string[] files = Directory.GetFiles(strFolderPath);
            if (files.Length == 0)
                return;

            foreach (string filePath in files)
            {
                try
                {
                    string strFileHash = objsha256.GetSHA256File(filePath);
                    Console.WriteLine($"f'sha256: {filePath} - {strFileHash} - {strFileHash.Length}");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"오류 발생 (파일: {Path.GetFileName(filePath)}): {e.Message}");
                }
            }
        }

        //AES
        private void f3()
        {
            string strKey = "abcdefghijklmnoprest123456789012";
            string strText = "문자열AES";

            objaes.setKey(strKey);
            string strEnc = objaes.EncryptText(strText);
            Console.WriteLine($"AES encrypt: {strEnc}) - {strEnc.Length}");

            string strDnc = objaes.DecryptText(strEnc);
            Console.WriteLine($"AES decrypt: {strDnc}) - {strDnc.Length}");
        }

    }
}
