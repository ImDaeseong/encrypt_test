import os
from MD5class import MD5
from SHA256class import SHA256
from AESclass import AES


def md5_text(text):
    try:
        md5 = MD5()
        strhash = md5.getMD5_text(text)
        print(f'MD5: "{text}" - {strhash} - {len(strhash)}')
    except Exception as e:
        print(f'오류 발생: {e}')


def md5_file(folderpath):
    if not os.path.exists(folderpath):
        print(f'오류 발생: 폴더 "{folderpath}"가 존재하지 않습니다.')
        return

    try:
        md5 = MD5()
        files = os.listdir(folderpath)
        if not files:
            print(f'폴더 "{folderpath}"에 파일이 없습니다.')
            return

        for file_name in files:
            file_path = os.path.join(folderpath, file_name)
            if os.path.isfile(file_path):
                try:
                    filehash = md5.getMD5_file(file_path)
                    print(f'md5: {file_path} - {filehash} - {len(filehash)}')
                except Exception as e:
                    print(f'오류 발생 (파일: {file_name}): {e}')
    except Exception as e:
        print(f'오류 발생 (md5_file): {e}')


def sha256_text(text):
    try:
        sha256 = SHA256()
        strhash = sha256.getSHA256_text(text)
        print(f'sha256: "{text}" - {strhash} - {len(strhash)}')
    except Exception as e:
        print(f'오류 발생: {e}')


def sha256_file(folderpath):
    if not os.path.exists(folderpath):
        print(f'오류 발생: 폴더 "{folderpath}"가 존재하지 않습니다.')
        return

    try:
        sha256 = SHA256()
        files = os.listdir(folderpath)
        if not files:
            print(f'폴더 "{folderpath}"에 파일이 없습니다.')
            return

        for file_name in files:
            file_path = os.path.join(folderpath, file_name)
            if os.path.isfile(file_path):
                try:
                    filehash = sha256.getSHA256_file(file_path)
                    print(f'sha256: {file_path} - {filehash} - {len(filehash)}')
                except Exception as e:
                    print(f'오류 발생 (파일: {file_name}): {e}')
    except Exception as e:
        print(f'오류 발생 (md5_file): {e}')


def aes_text(text):
    key = "abcdefghijklmnoprest123456789012"
    aes = AES(key)
    encrypt = aes.encrypt_text(text)
    print(f'AES encrypt: "{encrypt} - {len(encrypt)}')
    decrypt = aes.decrypt_text(encrypt)
    print(f'AES decrypt: "{decrypt} - {len(decrypt)}')


if __name__ == '__main__':
    md5_text('문자열md5')
    md5_file('E:\Battle.net')
    sha256_text('문자열sha256')
    sha256_file('E:\Battle.net')
    aes_text('문자열AES')
