import hashlib


GLOBAL_CERT = bytes.fromhex('''
30 82 01 0a 02 82 01 01 00 bf 65 30 f3 bd 67 e7 
a6 9d f8 db 18 b2 b9 c1 c0 5f fe fb e5 4b 91 df 
6f 38 da 51 cc ea c4 d3 04 bd 95 27 86 c1 13 ca 
73 15 44 4d 97 f5 10 b9 52 21 72 16 c8 b2 84 5f 
45 56 32 e7 c2 6b ad 2b d9 df 52 d6 e9 d1 2a ba 
35 e4 43 ab 54 e7 91 c5 ce d1 f1 ba a5 9f f4 ca 
db 89 04 3d f8 9f 6a 8b 8a 29 39 f8 4c 0d b8 a0 
6d 51 c4 74 24 64 fe 1a 23 97 f3 61 ea de c8 97 
dc 57 60 34 be 2c 18 50 3b d1 76 3b 49 2a 39 9a 
37 18 53 8f 1d 4c 82 b1 a0 33 43 57 19 ad 67 e7 
af 09 fb 04 54 a9 ea c0 c1 e9 32 6c 77 92 7f 9f 
7c 08 7c e8 a1 5d a4 fc 40 e6 6e 18 db bf 45 53 
4b 5c a7 9d f2 8f 7e 6c 04 b0 4d ee 99 25 9a 87 
84 6e 9e fe 3c 72 ec b0 64 dd 2e db ad 32 fa 1d 
4b 2c 1a 78 85 7c bc 2c d0 d7 83 77 5f 92 d5 db 
59 10 96 53 2e 5d c7 42 12 b8 61 cb 2c 5f 46 14 
9e 93 b0 53 21 a2 74 34 2d 02 03 01 00 01
''')


class RuntimeInfo:
    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        if file_path.endswith('.pyd'):
            self.extract_info_win64()
        else:
            # TODO: implement for other platforms
            self.extract_info_win64()

        self.serial_number = self.part_1[12:18].decode()
        self.runtime_aes_key = self.calc_aes_key()

    def __str__(self) -> str:
        trial = self.serial_number == '000000'
        product = ''
        for c in self.part_3[2:]:
            if 32 <= c <= 126:
                product += chr(c)
            else:
                break
        return f'''\
        ========================
        PyArmor Runtime ({'Trial' if trial else self.serial_number}) Information:
        Product: {product}
        AES key: {self.runtime_aes_key.hex()}
        Mix string AES nonce: {self.mix_str_aes_nonce().hex()}
        ========================'''

    def __repr__(self) -> str:
        return f'RuntimeInfo(part_1={self.part_1}, part_2={self.part_2}, part_3={self.part_3})'

    def extract_info_win64(self) -> None:
        '''
        Try to find useful information from `pyarmor_runtime.pyd` file,
        and store all three parts in the object.
        '''
        with open(self.file_path, 'rb') as f:
            data = f.read(16 * 1024 * 1024)
        cur = data.index(b'pyarmor-vax')

        self.part_1 = data[cur:cur+20]

        cur += 36
        part_2_offset = int.from_bytes(data[cur:cur+4], 'little')
        part_2_len = int.from_bytes(data[cur+4:cur+8], 'little')
        part_3_offset = int.from_bytes(data[cur+8:cur+12], 'little')
        cur += 16
        self.part_2 = data[cur+part_2_offset:cur+part_2_offset+part_2_len]

        cur += part_3_offset
        part_3_len = int.from_bytes(data[cur+4:cur+8], 'little')
        cur += 32
        self.part_3 = data[cur:cur+part_3_len]

    def calc_aes_key(self) -> bytes:
        return hashlib.md5(self.part_1 + self.part_2 + self.part_3 + GLOBAL_CERT).digest()

    def mix_str_aes_nonce(self) -> bytes:
        return self.part_3[:12]


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print('Usage: python runtime.py path/to/pyarmor_runtime[.pyd|.so|.dylib]')
        exit(1)
    for i in sys.argv[1:]:
        runtime = RuntimeInfo(i)
        print(runtime)
