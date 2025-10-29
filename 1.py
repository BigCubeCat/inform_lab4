import random


def keystream(key: str, length: int):
    """Генератор ключевой последовательности на основе seed."""
    random.seed(key)
    for _ in range(length):
        yield random.randint(0, 255)


def stream_cipher(data: str, key: str) -> str:
    """Шифрует или расшифровывает строку."""
    data_bytes = data.encode("utf-8")
    cipher_bytes = bytes(
        [b ^ k for b, k in zip(data_bytes, keystream(key, len(data_bytes)))]
    )
    return cipher_bytes.hex()


def stream_decipher(cipher_hex: str, key: str) -> str:
    """Расшифровывает строку из hex-представления."""
    cipher_bytes = bytes.fromhex(cipher_hex)
    plain_bytes = bytes(
        [b ^ k for b, k in zip(cipher_bytes, keystream(key, len(cipher_bytes)))]
    )
    return plain_bytes.decode("utf-8", errors="ignore")


if __name__ == "__main__":
    text = input("Введите строку для шифрования: ")
    key = input("Введите ключ: ")

    encrypted = stream_cipher(text, key)
    print(f"\nЗашифрованный текст (hex): {encrypted}")

    decrypted = stream_decipher(encrypted, key)
    print(f"Расшифрованный текст: {decrypted}")
