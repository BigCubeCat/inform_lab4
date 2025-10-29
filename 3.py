import struct
import math
import itertools
import random
from typing import Tuple
import numpy as np

# Для визуализации
import matplotlib.pyplot as plt
import pandas as pd

# ---------------------------
# Низкоуровневые утилиты
# ---------------------------


def rol(x: int, r: int, bits: int) -> int:
    return ((x << r) & ((1 << bits) - 1)) | (x >> (bits - r))


def ror(x: int, r: int, bits: int) -> int:
    return (x >> r) | ((x << (bits - r)) & ((1 << bits) - 1))


def int_to_bytes_be(x: int, length: int) -> bytes:
    return x.to_bytes(length, "big")


def bytes_to_int_be(b: bytes) -> int:
    return int.from_bytes(b, "big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------
# Простой блочный шифр (Feistel), блок 64 бита, ключ 128 бит
# ---------------------------
# Это не криптографически серьёзный шифр — учебная реализация для построения хеша.
# 12 раундов Feistel, функция F использует арифметику и вращения.

BLOCK_SIZE = 8  # bytes = 64 bits
KEY_SIZE = 16  # bytes = 128 bits
ROUNDS = 12
MASK32 = (1 << 32) - 1


def key_schedule(key: bytes):
    # Простая схема развёртки ключа: разбиваем 128-bit на четыре 32-bit слова,
    # затем для каждого раунда генерируем 32-bit подключ (вращением/сложением)
    if len(key) != KEY_SIZE:
        raise ValueError("Key must be 16 bytes")
    k_words = list(struct.unpack(">IIII", key))  # 4 words big-endian
    round_keys = []
    for i in range(ROUNDS):
        # комбинируем слова, применяем простые операции
        a = k_words[i % 4]
        b = k_words[(i + 1) % 4]
        rk = (a ^ (b + i)) & MASK32
        # небольшая нелинейность
        rk = rol(rk, (i * 5 + 3) % 32, 32) ^ (0x9E3779B9 & MASK32)  # константа Кнаккер?
        round_keys.append(rk)
    return round_keys


def F_func(r: int, rk: int) -> int:
    # F: 32-bit -> 32-bit
    # простая нелинейная смесь: вращения, умножение, XOR, добавление констант
    x = (r ^ rk) & MASK32
    x = (x + 0xA5A5A5A5) & MASK32
    x = rol(x, (x & 31), 32)
    # нелинейность через умножение по модулю 2^32
    x = (x * 0x7FED7FED) & MASK32
    x = x ^ ((x >> 16) | (x << 16) & MASK32)
    return x & MASK32


def encrypt_block(block: bytes, key: bytes) -> bytes:
    """Feistel encryption of 64-bit block"""
    if len(block) != BLOCK_SIZE:
        raise ValueError("Block must be 8 bytes")
    L, R = struct.unpack(">II", block)  # два 32-битных слова
    round_keys = key_schedule(key)
    for rk in round_keys:
        newL = R
        newR = L ^ F_func(R, rk)
        L, R = newL & MASK32, newR & MASK32
    return struct.pack(">II", L, R)


def decrypt_block(block: bytes, key: bytes) -> bytes:
    # Для проверки — обратный процесс
    if len(block) != BLOCK_SIZE:
        raise ValueError("Block must be 8 bytes")
    L, R = struct.unpack(">II", block)
    round_keys = key_schedule(key)
    for rk in reversed(round_keys):
        newR = L
        newL = R ^ F_func(L, rk)
        L, R = newL & MASK32, newR & MASK32
    return struct.pack(">II", L, R)


# ---------------------------
# Хеш-функция: Davies–Meyer + Merkle–Damgård
# ---------------------------
# Davies–Meyer: H_i = E(M_i, H_{i-1}) XOR H_{i-1}
# Блок шифра 64 бита -> размер внутреннего состояния 64 бита.
# Паддинг: аналог SHA: 0x80, нули, затем 64-битная длина (бит) в конце.


def md_pad(message: bytes, block_size_bytes: int = BLOCK_SIZE) -> bytes:
    ml_bits = len(message) * 8
    # Добавляем 0x80
    padded = message + b"\x80"
    # добавляем нули, чтобы осталось место для 8-байтового представления длины
    pad_len = (-len(padded) - 8) % block_size_bytes
    padded += b"\x00" * pad_len
    padded += struct.pack(">Q", ml_bits)  # 8 bytes big-endian length
    return padded


def dm_hash(
    message: bytes, iv: int = 0x0123456789ABCDEF, key_const: bytes = None
) -> bytes:
    """
    hash(message): возвращает 8-байтовый дайджест.
    iv: 64-bit initial chaining value (int).
    key_const: if provided, used to derive per-block keys (or randomize). If None, we'll use block as key + const.
    """
    if key_const is None:
        # простой ключ по умолчанию (16 байт)
        key_const = b"DM_SIMPLE_KEY_16"  # 16 bytes
    if len(key_const) != KEY_SIZE:
        key_const = key_const.ljust(KEY_SIZE, b"\x00")[:KEY_SIZE]
    H = iv & ((1 << 64) - 1)
    padded = md_pad(message, BLOCK_SIZE)
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i : i + BLOCK_SIZE]  # 8 bytes
        # Для безопасности key зависит от блока: расширяем block до 16 байт xor с константой
        key = bytes(
            a ^ b for a, b in zip(key_const, block + block)
        )  # block repeated to 16 bytes
        C = encrypt_block(
            int_to_bytes_be(H, BLOCK_SIZE), key
        )  # шифруем состояние как "plaintext"
        C_int = bytes_to_int_be(C)
        H = C_int ^ H  # Davies–Meyer
        H &= (1 << 64) - 1
    return int_to_bytes_be(H, BLOCK_SIZE)


def hexdigest(message: bytes) -> str:
    return dm_hash(message).hex()


# ---------------------------
# Тесты корректности (самопроверка шифра)
# ---------------------------
def self_test_cipher():
    key = b"0123456789ABCDEF"
    block = b"\x00" * 8
    c = encrypt_block(block, key)
    p = decrypt_block(c, key)
    ok = p == block
    return ok, c.hex()


# ---------------------------
# Проверка лавинного эффекта
# ---------------------------
def hamming_distance_bytes(a: bytes, b: bytes) -> int:
    assert len(a) == len(b)
    dist = 0
    for x, y in zip(a, b):
        dist += bin(x ^ y).count("1")
    return dist


def avalanche_test(message: bytes, flips: int = None):
    """
    Проверка лавинного эффекта:
    - Поочерёдно меняем каждый бит во входном сообщении и считаем расстояние Хэмминга между хешами.
    - Если flips задан, тестируем только первые flips битов.
    Возвращаем DataFrame с результатами.
    """
    base_hash = dm_hash(message)
    msg_bits = len(message) * 8
    if flips is None or flips > msg_bits:
        flips = msg_bits
    results = []
    msg_int = bytes_to_int_be(message)
    for bit in range(flips):
        # flip bit (нумерация от MSB блока 0 до LSB)
        # Создаём маску: будем менять биты в big-endian представлении
        mask = 1 << (msg_bits - 1 - bit)
        mod_int = msg_int ^ mask
        mod_message = int_to_bytes_be(mod_int, len(message))
        h2 = dm_hash(mod_message)
        dist = hamming_distance_bytes(base_hash, h2)
        results.append({"bit_index": bit, "hamming_distance": dist})
    df = pd.DataFrame(results)
    return base_hash, df


# ---------------------------
# Демонстрация и запуск тестов
# ---------------------------

# 1) самотест шифра
ok, sample_cipher = self_test_cipher()

# 2) пример хешей
examples = [
    b"",
    b"a",
    b"abc",
    b"The quick brown fox jumps over the lazy dog",
    b"The quick brown fox jumps over the lazy dog.",
]
example_hashes = [(ex, hexdigest(ex)) for ex in examples]

# 3) лавинный эффект: возьмём разумную длину сообщения (например 16 байт) и протестируем первые 128 бит
msg = b"Example message."  # 16 bytes
base_hash, df = avalanche_test(msg, flips=128)

# Статистика
avg = df["hamming_distance"].mean()
median = df["hamming_distance"].median()
std = df["hamming_distance"].std()
minv = df["hamming_distance"].min()
maxv = df["hamming_distance"].max()

# Ожидаемая "идеальная" половина битов отличаться: 64-bit output -> 32 bits on average
expected = 64 / 2

# Выводим результаты
print("=== Self-test блока ===")
print("Шифр корректно расшифровывает блок? ", ok)
print("Пример шифротекста нулевого блока: ", sample_cipher)
print()

print("=== Примеры хешей (hex) ===")
for ex, h in example_hashes:
    print(f"message={ex!r:40}  hash={h}")
print()

print("=== Лавинный эффект: статистика ===")
print(f"Сообщение для теста (len={len(msg)} байт): {msg!r}")
print(f"Среднее Hamming distance: {avg:.3f} (ожидаем примерно {expected})")
print(f"Медиана: {median}, std: {std:.3f}, min: {minv}, max: {maxv}")
print()

# Покажем распределение гистограммой
plt.figure(figsize=(8, 4))
plt.hist(df["hamming_distance"], bins=range(0, 65))
plt.title("Распределение Hamming distance при побитовом изменении входного сообщения")
plt.xlabel("Hamming distance (количество отличающихся бит в выходе, 64 бита)")
plt.ylabel("Число случаев")
plt.grid(True)
plt.show()

# Показать первые 10 результатов в табличном виде
top10 = df.head(10)
import caas_jupyter_tools as jt

jt.display_dataframe_to_user("Avalanche Test (first 10 rows)", top10)

# Дополнительно: гистограмма и суммарная статистика в таблице
summary_table = pd.DataFrame(
    {
        "mean": [avg],
        "median": [median],
        "std": [std],
        "min": [minv],
        "max": [maxv],
        "output_bits": [64],
        "expected_mean": [expected],
    }
)
jt.display_dataframe_to_user("Avalanche Summary", summary_table)

# Финальные примеры — покажем base_hash
print("Базовый хеш для сообщения:", base_hash.hex())
