#!/usr/bin/env python3
"""
Шифрование/расшифрование файла алгоритмом Кузнечик (GOST R 34.12-2015)
на Python с использованием библиотеки gostcrypto.
Режим: CBC + PKCS#7 паддинг.

Использование:
    python file_cipher_kuznechik.py encrypt input_file output_file
    python file_cipher_kuznechik.py decrypt input_file output_file
"""

import sys
import os
import gostcrypto

# === Константа ключа (256 бит / 64 hex-символа) ===
# !!! Секретный ключ должен быть уникальным и храниться безопасно !!!
KEY_HEX = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"

BLOCK_SIZE = 16  # байт


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if len(data) == 0 or len(data) % block_size != 0:
        raise ValueError("Неверная длина данных для удаления PKCS7-паддинга.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Недопустимая длина паддинга.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Неверные байты паддинга.")
    return data[:-pad_len]


def hex_to_key(hexstr: str) -> bytes:
    hexstr = hexstr.strip()
    if len(hexstr) != 64:
        raise ValueError("Ключ должен быть 64 hex-символа (256 бит).")
    return bytes.fromhex(hexstr)


def encrypt_file(key: bytes, infile: str, outfile: str):
    iv = os.urandom(BLOCK_SIZE)
    cipher = gostcrypto.gostcipher.new(
        "kuznechik", key, gostcrypto.gostcipher.MODE_CBC, init_vect=iv
    )
    with open(infile, "rb") as fin, open(outfile, "wb") as fout:
        fout.write(iv)  # сохраняем IV в начало
        data = fin.read()
        padded = pkcs7_pad(data)
        ciphertext = cipher.encrypt(padded)
        fout.write(ciphertext)


def decrypt_file(key: bytes, infile: str, outfile: str):
    with open(infile, "rb") as fin:
        iv = fin.read(BLOCK_SIZE)
        if len(iv) != BLOCK_SIZE:
            raise ValueError("Файл слишком короткий — отсутствует IV.")
        cipher = gostcrypto.gostcipher.new(
            "kuznechik", key, gostcrypto.gostcipher.MODE_CBC, init_vect=iv
        )
        ciphertext = fin.read()
        plaintext_padded = cipher.decrypt(ciphertext)
        plaintext = pkcs7_unpad(plaintext_padded)
        with open(outfile, "wb") as fout:
            fout.write(plaintext)


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(2)

    mode = sys.argv[1].lower()
    infile = sys.argv[2]
    outfile = sys.argv[3]

    try:
        key = hex_to_key(KEY_HEX)
    except ValueError as e:
        print(f"Ошибка в ключе: {e}")
        sys.exit(2)

    try:
        if mode == "encrypt":
            encrypt_file(key, infile, outfile)
            print(f"✅ Файл зашифрован: {outfile}")
        elif mode == "decrypt":
            decrypt_file(key, infile, outfile)
            print(f"✅ Файл расшифрован: {outfile}")
        else:
            print("Укажите режим: encrypt или decrypt.")
            sys.exit(2)
    except Exception as e:
        print(f"Ошибка: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
