#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

class Salsa20 {
public:
  // key: 16 or 32 bytes. nonce: exactly 8 bytes.
  Salsa20(const std::vector<uint8_t> &key, const std::array<uint8_t, 8> &nonce);

  // XOR шифрование/дешифрование in -> out (in and out могут ссылаться на ту же
  // память).
  void process(const uint8_t *in, uint8_t *out, size_t len);

  // Удобные обёртки для std::string
  std::string processString(const std::string &input);

  // Сброс счётчика в ноль (если нужно зашифровать новый поток с тем же
  // ключом+nonce).
  void resetCounter();

private:
  void salsa20_block(uint8_t out[64], const uint32_t input[16]) const;
  static uint32_t rotl(uint32_t v, int c);

  std::array<uint32_t, 16>
      m_state_template; // шаблон состояния (константы, ключ, nonce, counter=0)
  uint64_t m_block_counter; // 64-битный блоковый счётчик (каждый блок 64 байта)
  bool m_is_32byte_key;
};
