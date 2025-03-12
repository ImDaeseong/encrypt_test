import hashlib


class MD5:
    def getMD5_text(self, text):
        md5hash = hashlib.md5()
        md5hash.update(text.encode('utf-8'))
        return md5hash.hexdigest()

    def getMD5_file(self, filepath, chunk_size=8192):
        md5hash = hashlib.md5()
        try:
            with open(filepath, 'rb') as file:
                for chunk in iter(lambda: file.read(chunk_size), b''):
                    md5hash.update(chunk)
            return md5hash.hexdigest()
        except IOError as e:
            raise IOError(f"파일 읽기 오류: {e}")
