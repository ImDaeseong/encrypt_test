#include "pch.h"
#include "framework.h"
#include "MFCApplication1.h"
#include "MFCApplication1Dlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

CMFCApplication1Dlg::CMFCApplication1Dlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_MFCAPPLICATION1_DIALOG, pParent)
{
}

void CMFCApplication1Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CMFCApplication1Dlg, CDialogEx)
	ON_WM_PAINT()
END_MESSAGE_MAP()

BOOL CMFCApplication1Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	Test1();
	Test2();
	Test3();
	
	return TRUE;  
}
 
void CMFCApplication1Dlg::OnPaint()
{
	CPaintDC dc(this);
}

void CMFCApplication1Dlg::Test1()
{
	CString strText = CString("문자열md5");
	std::string textHash = CMD5::GetMD5FromText(std::string(CT2A(strText)));

	CString strMsg;
	strMsg.Format(_T("MD5: %s - %s - %d \n"), strText, CString(textHash.c_str()), textHash.length());
	OutputDebugString(strMsg);

	CString strFolderPath = CString("E:\\Battle.net");
	CString strSearchPath = strFolderPath + _T("\\*.*");
	WIN32_FIND_DATA findData;
	HANDLE hFind = FindFirstFile(strSearchPath, &findData);
	if (hFind == INVALID_HANDLE_VALUE)
		return;

    do
    {
        // 디렉토리 항목 건너뛰기
        if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || !_tcscmp(findData.cFileName, _T(".")) || !_tcscmp(findData.cFileName, _T("..")))
            continue;
        
        CString strFilePath = strFolderPath + _T("\\") + findData.cFileName;

		std::string fileHash = CMD5::GetMD5FromFile(std::string(CT2A(strFilePath)));
        
		strMsg.Format(_T("MD5: %s - %s - %d \n"), strFilePath, CString(fileHash.c_str()), fileHash.length());
		OutputDebugString(strMsg);

    } while (FindNextFile(hFind, &findData));

    FindClose(hFind);
}

void CMFCApplication1Dlg::Test2()
{
	CString strText = CString("문자열sha256");
	std::string textHash = CSHA256::GetSHA256FromText(std::string(CT2A(strText)));

	CString strMsg;
	strMsg.Format(_T("sha256: %s - %s - %d \n"), strText, CString(textHash.c_str()), textHash.length());
	OutputDebugString(strMsg);

	CString strFolderPath = CString("E:\\Battle.net");
	CString strSearchPath = strFolderPath + _T("\\*.*");
	WIN32_FIND_DATA findData;
	HANDLE hFind = FindFirstFile(strSearchPath, &findData);
	if (hFind == INVALID_HANDLE_VALUE)
		return;

	do
	{
		// 디렉토리 항목 건너뛰기
		if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || !_tcscmp(findData.cFileName, _T(".")) || !_tcscmp(findData.cFileName, _T("..")))
			continue;

		CString strFilePath = strFolderPath + _T("\\") + findData.cFileName;

		std::string fileHash = CSHA256::GetSHA256FromFile(std::string(CT2A(strFilePath)));

		strMsg.Format(_T("sha256: %s - %s - %d \n"), strFilePath, CString(fileHash.c_str()), fileHash.length());
		OutputDebugString(strMsg);

	} while (FindNextFile(hFind, &findData));

	FindClose(hFind);
}

void CMFCApplication1Dlg::Test3()
{
	std::string key = "abcdefghijklmnoprest123456789012";
	std::string plainText = "문자열AES";

	CAES aes(key);
	std::string encryptedText = aes.EncryptText(plainText);
	std::string decryptedText = aes.DecryptText(encryptedText);

	CString strMsg;
	strMsg.Format(_T("AES encrypt: %s - %d \n"),  CString(encryptedText.c_str()), encryptedText.length());
	OutputDebugString(strMsg);

	strMsg.Format(_T("AES decrypt: %s - %d \n"), CString(decryptedText.c_str()), decryptedText.length());
	OutputDebugString(strMsg);
}