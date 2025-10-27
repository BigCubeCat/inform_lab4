#include "salsa20.hpp"

#include <array>
#include <cstdint>
#include <vector>

// "expand 32-byte k" в виде 4 слов (little-endian ASCII)
static const std::array<uint8_t, 16> sigma = { 'e', 'x', 'p', 'a', 'n', 'd',
                                               ' ', '3', '2', '-', 'b', 'y',
                                               't', 'e', ' ', 'k' };

static inline uint32_t load32_le(const uint8_t *b) {
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16)
           | ((uint32_t)b[3] << 24);
}

static inline void store32_le(uint8_t *b, uint32_t v) {
    b[0] = (uint8_t)(v & 0xff);
    b[1] = (uint8_t)((v >> 8) & 0xff);
    b[2] = (uint8_t)((v >> 16) & 0xff);
    b[3] = (uint8_t)((v >> 24) & 0xff);
}

Salsa20::Salsa20(
    const std::vector<uint8_t> &key, const std::array<uint8_t, 8> &nonce
) {
    if (key.size() != 16 && key.size() != 32) {
        throw std::invalid_argument("Salsa20: key must be 16 or 32 bytes");
    }

    m_is_32byte_key = (key.size() == 32);
    m_block_counter = 0;

    // построим m_state_template (16 слов)
    // формат состояния (DWORD = 32-bit little-endian):
    //  0: sigma[0..3]
    //  1..4: key[0..15]
    //  5: sigma[4..7]
    //  6..7: nonce (8 bytes -> 2 words)
    //  8..9: block counter (initialized 0) - low word at 8, high word at 9
    // 10: sigma[8..11]
    // 11..14: key[16..31] (or repeat key[0..15] if 16-byte key)
    // 15: sigma[12..15]

    m_state_template.fill(0);

    // constants
    m_state_template[0]  = load32_le(sigma.data() + 0);
    m_state_template[5]  = load32_le(sigma.data() + 4);
    m_state_template[10] = load32_le(sigma.data() + 8);
    m_state_template[15] = load32_le(sigma.data() + 12);

    // key first 16 bytes -> words 1..4
    for (int i = 0; i < 4; ++i) {
        m_state_template[1 + i] = load32_le(&key[i * 4]);
    }

    // key second 16 bytes -> words 11..14 (if 16-byte key, repeat first 16)
    if (m_is_32byte_key) {
        for (int i = 0; i < 4; ++i) {
            m_state_template[11 + i] = load32_le(&key[16 + i * 4]);
        }
    }
    else {
        // 16-byte key -> repeat
        for (int i = 0; i < 4; ++i) {
            m_state_template[11 + i] = load32_le(&key[i * 4]);
        }
    }

    // nonce words (little-endian)
    m_state_template[6] = load32_le(nonce.data() + 0);
    m_state_template[7] = load32_le(nonce.data() + 4);

    // counter words (initially zero)
    m_state_template[8] = 0;
    m_state_template[9] = 0;
}

uint32_t Salsa20::rotl(uint32_t v, int c) {
    return (v << c) | (v >> (32 - c));
}

// Salsa20 core: принимает input[16] слов, выполняет 20 раундов и пишет 64 байта
// в out
void Salsa20::salsa20_block(uint8_t out[64], const uint32_t input[16]) const {
    uint32_t x[16];
    for (int i = 0; i < 16; ++i)
        x[i] = input[i];

    // 10 двойных раундов = 20 раундов
    for (int i = 0; i < 10; ++i) {
        // column round
        x[4] ^= rotl(x[0] + x[12], 7);
        x[8] ^= rotl(x[4] + x[0], 9);
        x[12] ^= rotl(x[8] + x[4], 13);
        x[0] ^= rotl(x[12] + x[8], 18);

        x[9] ^= rotl(x[5] + x[1], 7);
        x[13] ^= rotl(x[9] + x[5], 9);
        x[1] ^= rotl(x[13] + x[9], 13);
        x[5] ^= rotl(x[1] + x[13], 18);

        x[14] ^= rotl(x[10] + x[6], 7);
        x[2] ^= rotl(x[14] + x[10], 9);
        x[6] ^= rotl(x[2] + x[14], 13);
        x[10] ^= rotl(x[6] + x[2], 18);

        x[3] ^= rotl(x[15] + x[11], 7);
        x[7] ^= rotl(x[3] + x[15], 9);
        x[11] ^= rotl(x[7] + x[3], 13);
        x[15] ^= rotl(x[11] + x[7], 18);

        // row round
        x[1] ^= rotl(x[0] + x[3], 7);
        x[2] ^= rotl(x[1] + x[0], 9);
        x[3] ^= rotl(x[2] + x[1], 13);
        x[0] ^= rotl(x[3] + x[2], 18);

        x[6] ^= rotl(x[5] + x[4], 7);
        x[7] ^= rotl(x[6] + x[5], 9);
        x[4] ^= rotl(x[7] + x[6], 13);
        x[5] ^= rotl(x[4] + x[7], 18);

        x[11] ^= rotl(x[10] + x[9], 7);
        x[8] ^= rotl(x[11] + x[10], 9);
        x[9] ^= rotl(x[8] + x[11], 13);
        x[10] ^= rotl(x[9] + x[8], 18);

        x[12] ^= rotl(x[15] + x[14], 7);
        x[13] ^= rotl(x[12] + x[15], 9);
        x[14] ^= rotl(x[13] + x[12], 13);
        x[15] ^= rotl(x[14] + x[13], 18);
    }

    // add original input and store as little-endian bytes
    for (int i = 0; i < 16; ++i) {
        uint32_t result = x[i] + input[i];
        store32_le(out + 4 * i, result);
    }
}

void Salsa20::process(const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t keystream[64];
    size_t remaining = len;
    size_t offset    = 0;

    while (remaining > 0) {
        // подготовим input для блока: скопируем шаблон и вставим счётчик
        uint32_t input[16];
        for (int i = 0; i < 16; ++i)
            input[i] = m_state_template[i];

        // поместим счётчик (64 бит) в слова 8 (low) и 9 (high)
        uint64_t ctr = m_block_counter;
        input[8]     = static_cast<uint32_t>(ctr & 0xffffffffu);
        input[9]     = static_cast<uint32_t>((ctr >> 32) & 0xffffffffu);

        salsa20_block(keystream, input);

        size_t take = (remaining >= 64) ? 64 : remaining;
        for (size_t i = 0; i < take; ++i) {
            out[offset + i] = in[offset + i] ^ keystream[i];
        }

        remaining -= take;
        offset += take;
        ++m_block_counter;
    }
}

std::string Salsa20::processString(const std::string &input) {
    std::string out;
    out.resize(input.size());
    if (!input.empty()) {
        process(
            reinterpret_cast<const uint8_t *>(input.data()),
            reinterpret_cast<uint8_t *>(&out[0]),
            input.size()
        );
    }
    return out;
}

void Salsa20::resetCounter() {
    m_block_counter = 0;
}
