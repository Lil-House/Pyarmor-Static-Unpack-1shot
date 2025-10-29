import hashlib


GLOBAL_CERT = bytes.fromhex("""
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
""")


class RuntimeInfo:
    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        if file_path.endswith(".pyd"):
            self.extract_info_win64()
        else:
            # TODO: implement for other platforms
            self.extract_info_win64()

        self.serial_number = self.part_1[12:18].decode()
        self.runtime_aes_key = self.calc_aes_key()

    def __str__(self) -> str:
        trial = self.serial_number == "000000"
        product = ""
        for c in self.part_3[2:]:
            if 32 <= c <= 126:
                product += chr(c)
            else:
                break
        return f"""\
        ========================
        Pyarmor Runtime ({"Trial" if trial else self.serial_number}) Information:
        Product: {product}
        AES key: {self.runtime_aes_key.hex()}
        Mix string AES nonce: {self.mix_str_aes_nonce().hex()}
        ========================"""

    def __repr__(self) -> str:
        return f"RuntimeInfo(part_1={self.part_1}, part_2={self.part_2}, part_3={self.part_3})"

    def extract_info_win64(self) -> None:
        """
        Try to find useful information from `pyarmor_runtime.pyd` file,
        and store all three parts in the object.
        """
        with open(self.file_path, "rb") as f:
            data = f.read(16 * 1024 * 1024)
        cur = data.index(b"pyarmor-vax")

        if data[cur + 11 : cur + 18] == b"\x00" * 7:
            raise ValueError(f"{self.file_path} is a runtime template")

        self.part_1 = data[cur : cur + 20]

        cur += 36
        part_2_offset = int.from_bytes(data[cur : cur + 4], "little")
        part_2_len = int.from_bytes(data[cur + 4 : cur + 8], "little")
        part_3_offset = int.from_bytes(data[cur + 8 : cur + 12], "little")
        cur += 16
        self.part_2 = data[cur + part_2_offset : cur + part_2_offset + part_2_len]

        cur += part_3_offset
        part_3_len = int.from_bytes(data[cur + 4 : cur + 8], "little")
        cur += 32
        self.part_3 = data[cur : cur + part_3_len]

    def calc_aes_key(self) -> bytes:
        return hashlib.md5(
            self.part_1 + self.part_2 + self.part_3 + GLOBAL_CERT
        ).digest()

    def mix_str_aes_nonce(self) -> bytes:
        return self.part_3[:12]

    @classmethod
    def default(cls) -> "RuntimeInfo":
        instance = cls.__new__(cls)
        instance.file_path = "<default>"
        instance.part_1 = b"pyarmor-vax-000000\x00\x00"
        instance.part_2 = bytes.fromhex("""
            30 81 89 02 81 81 00 A8 ED 64 F4 83 49 13 FC 0F
            86 6F 00 5A 8F E4 91 AA ED 1C EA D4 BB 4C 3F 7C
            24 21 01 A8 D0 7D 93 F4 BF E7 FB 8C 06 57 88 6A
            2E 9B 54 53 D5 7B 8F F6 83 DF 72 00 42 A3 2D 18
            30 AD 3A E4 F1 E4 3A 3C 8C EA F5 46 F3 BB 75 62
            11 84 FB 3F 3B 4C 35 61 4E 46 A1 E0 9E 3C B6 7A
            BA 52 C5 B6 40 F6 AD AB BC D5 CF 5B 40 CB 8D 13
            C4 28 B8 90 93 C4 76 01 09 8E 05 1E 61 FA 90 4C
            BF 67 D4 A7 D5 82 C1 02 03 01 00 01
            """)
        instance.part_3 = bytes.fromhex("""
            69 2E 6E 6F 6E 2D 70 72 6F 66 69 74 73 E7 5A 41
            9B DC 77 53 CA 1D E7 04 EB EF DA C9 A3 6C 0F 7B
            00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            00 00 00 00 00 00 00
            """)
        instance.serial_number = "000000"
        instance.runtime_aes_key = instance.calc_aes_key()
        return instance


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python runtime.py path/to/pyarmor_runtime[.pyd|.so|.dylib]")
        exit(1)
    for i in sys.argv[1:]:
        runtime = RuntimeInfo(i)
        print(runtime)
