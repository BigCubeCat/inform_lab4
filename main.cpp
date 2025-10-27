// example.cpp
#include "salsa20.hpp"
#include <iomanip>
#include <iostream>
#include <vector>

int main() {
  // Пример: 32-байтный ключ и 8-байтный nonce
  std::vector<uint8_t> key(32, 0);
  for (int i = 0; i < 32; ++i)
    key[i] = (uint8_t)i;

  std::array<uint8_t, 8> nonce = {0x00, 0x00, 0x00, 0x09,
                                  0x00, 0x00, 0x00, 0x4a};

  Salsa20 s1(key, nonce);

  std::string plaintext = "The quick brown fox jumps over the lazy dog";
  std::cout << "Plaintext: " << plaintext << "\n";

  std::string cipher = s1.processString(plaintext);

  // Показать шифротекст в hex
  std::cout << "Cipher hex: ";
  for (unsigned char c : cipher) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c;
  }
  std::cout << std::dec << "\n";

  // Дешифруем: нужно сбросить счётчик или создать новый объект с тем же
  // ключом+nonce
  Salsa20 s2(key, nonce);
  std::string recovered = s2.processString(cipher);

  std::cout << "Recovered: " << recovered << "\n";

  if (recovered == plaintext) {
    std::cout << "OK: decrypted matches plaintext\n";
  } else {
    std::cout << "ERROR: mismatch\n";
  }

  return 0;
}
