#include <iostream>
#include <vector>
#include <cstdint>
#include <string>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <random>
#include <algorithm>
#include <cstring>


using namespace std;

// SM4算法参数定义（复用原SM4实现）
const int SM4_BLOCK_SIZE = 16;  // 128位块大小
const int SM4_KEY_SIZE = 16;    // 128位密钥大小
const int ROUND_KEY_NUM = 32;   // 轮密钥数量

// S盒（复用）
static const uint8_t S_BOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

// 系统参数FK（复用）
static const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

// 固定参数CK（复用）
static const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

// 循环左移函数（复用）
uint32_t rotate_left(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// 字节替换函数τ（复用）
uint32_t t_1(uint32_t x) {
    uint32_t y = 0;
    y |= (uint32_t)S_BOX[(x >> 24) & 0xFF] << 24;
    y |= (uint32_t)S_BOX[(x >> 16) & 0xFF] << 16;
    y |= (uint32_t)S_BOX[(x >> 8) & 0xFF] << 8;
    y |= (uint32_t)S_BOX[x & 0xFF];
    return y;
}

// 线性变换函数L（复用）
uint32_t l_1(uint32_t x) {
    return x ^ rotate_left(x, 2) ^ rotate_left(x, 10) ^ rotate_left(x, 18) ^ rotate_left(x, 24);
}

// 合成置换T（复用）
uint32_t t(uint32_t x) {
    return l_1(t_1(x));
}

// 轮密钥生成中的线性变换函数L'（复用）
uint32_t l_2(uint32_t x) {
    return x ^ rotate_left(x, 13) ^ rotate_left(x, 23);
}

// 轮密钥生成中的合成置换T'（复用）
uint32_t t_(uint32_t x) {
    return l_2(t_1(x));
}

// 生成轮密钥（复用）
vector<uint32_t> generate_round_keys(const vector<uint8_t>& key) {
    vector<uint32_t> round_keys(ROUND_KEY_NUM);
    vector<uint32_t> k(4 + ROUND_KEY_NUM);

    for (int i = 0; i < 4; i++) {
        k[i] = (key[i * 4] << 24) | (key[i * 4 + 1] << 16) | (key[i * 4 + 2] << 8) | key[i * 4 + 3];
        k[i] ^= FK[i];
    }

    for (int i = 0; i < ROUND_KEY_NUM; i++) {
        k[i + 4] = k[i] ^ t_(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]);
        round_keys[i] = k[i + 4];
    }

    return round_keys;
}

// SM4加密单块（复用）
vector<uint8_t> sm4_encrypt_block(const vector<uint8_t>& plaintext, const vector<uint32_t>& round_keys) {
    vector<uint8_t> ciphertext(SM4_BLOCK_SIZE);
    vector<uint32_t> x(36);

    for (int i = 0; i < 4; i++) {
        x[i] = (plaintext[i * 4] << 24) | (plaintext[i * 4 + 1] << 16) | (plaintext[i * 4 + 2] << 8) | plaintext[i * 4 + 3];
    }

    for (int i = 0; i < 32; i++) {
        x[i + 4] = x[i] ^ t(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ round_keys[i]);
    }

    for (int i = 0; i < 4; i++) {
        uint32_t temp = x[35 - i];
        ciphertext[i * 4] = (temp >> 24) & 0xFF;
        ciphertext[i * 4 + 1] = (temp >> 16) & 0xFF;
        ciphertext[i * 4 + 2] = (temp >> 8) & 0xFF;
        ciphertext[i * 4 + 3] = temp & 0xFF;
    }

    return ciphertext;
}

// 字节数组转16进制字符串（复用）
string bytes_to_hex(const vector<uint8_t>& bytes) {
    stringstream ss;
    ss << hex << setfill('0');
    for (uint8_t b : bytes) {
        ss << setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

// 16进制字符串转字节数组（复用）
vector<uint8_t> hex_to_bytes(const string& hex) {
    vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byte_str = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byte_str.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// 生成随机16进制字符串（复用）
string generateRandomHexString(size_t length) {
    static const char hexDigits[] = "0123456789abcdef";
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 15);

    string result(length, ' ');
    generate_n(result.begin(), length, [&]() {
        return hexDigits[dis(gen)];
        });

    return result;
}


// ---------------------- GCM模式实现 ----------------------

// 定义128位块（用于GF(2^128)运算）
struct gcm_block {
    uint64_t hi;  // 高64位
    uint64_t lo;  // 低64位

    gcm_block() : hi(0), lo(0) {}
    gcm_block(uint64_t h, uint64_t l) : hi(h), lo(l) {}
};

// 两个128位块异或
gcm_block gcm_xor(const gcm_block& a, const gcm_block& b) {
    return gcm_block(a.hi ^ b.hi, a.lo ^ b.lo);
}

// 128位块左移1位并按不可约多项式x^128 + x^7 + x^2 + x + 1约简
gcm_block gcm_shift_left1(const gcm_block& x) {
    gcm_block res;
    res.hi = (x.hi << 1) | (x.lo >> 63);  // 高64位左移，低64位最高位补入
    res.lo = x.lo << 1;                    // 低64位左移

    // 若原最高位为1，异或约简多项式（0x87）
    if (x.hi & (1ULL << 63)) {
        res.lo ^= 0x87;
    }
    return res;
}

// GF(2^128)乘法（优化版：按8位分组处理，减少循环次数）
gcm_block gcm_multiply(const gcm_block& a, const gcm_block& b) {
    gcm_block res;
    gcm_block temp = a;

    // 预计算a左移0-7位的结果（带约简）
    gcm_block shifts[8];
    shifts[0] = a;
    for (int i = 1; i < 8; ++i) {
        shifts[i] = gcm_shift_left1(shifts[i - 1]);
    }

    // 处理低64位（8组×8位）
    for (int i = 0; i < 8; ++i) {
        uint8_t byte = (b.lo >> (i * 8)) & 0xFF;
        for (int j = 0; j < 8; ++j) {
            if (byte & (1 << j)) {
                res = gcm_xor(res, shifts[(i * 8 + j) % 8]);
            }
        }
        temp = shifts[7];  // 左移8位（复用预计算结果）
    }

    // 处理高64位（8组×8位）
    for (int i = 0; i < 8; ++i) {
        uint8_t byte = (b.hi >> (i * 8)) & 0xFF;
        for (int j = 0; j < 8; ++j) {
            if (byte & (1 << j)) {
                gcm_block shift = a;
                // 左移64 + i*8 + j位（优化：循环展开）
                for (int k = 0; k < 64 + i * 8 + j; ++k) {
                    shift = gcm_shift_left1(shift);
                }
                res = gcm_xor(res, shift);
            }
        }
    }

    return res;
}

// 字节数组转128位块（大端序）
gcm_block bytes_to_gcm_block(const vector<uint8_t>& bytes, size_t offset = 0) {
    gcm_block block;
    uint8_t buf[16] = { 0 };
    size_t len = min(16ULL, bytes.size() - offset);
    memcpy(buf, &bytes[offset], len);

    // 高64位（前8字节）
    block.hi = 0;
    for (int i = 0; i < 8; ++i) {
        block.hi = (block.hi << 8) | buf[i];
    }
    // 低64位（后8字节）
    block.lo = 0;
    for (int i = 8; i < 16; ++i) {
        block.lo = (block.lo << 8) | buf[i];
    }
    return block;
}

// 128位块转字节数组（大端序）
vector<uint8_t> gcm_block_to_bytes(const gcm_block& block) {
    vector<uint8_t> bytes(16);
    for (int i = 0; i < 8; ++i) {
        bytes[i] = (block.hi >> (8 * (7 - i))) & 0xFF;
    }
    for (int i = 0; i < 8; ++i) {
        bytes[8 + i] = (block.lo >> (8 * (7 - i))) & 0xFF;
    }
    return bytes;
}

// GHASH函数：计算认证标签的核心（AAD和密文的哈希）
gcm_block ghash(const gcm_block& H, const vector<uint8_t>& AAD, const vector<uint8_t>& ciphertext) {
    gcm_block state;  // 初始为0

    // 处理AAD（按128位块）
    size_t aad_len = AAD.size();
    for (size_t offset = 0; offset < aad_len; offset += 16) {
        gcm_block a_block = bytes_to_gcm_block(AAD, offset);
        state = gcm_xor(state, a_block);
        state = gcm_multiply(state, H);
    }

    // 处理密文（按128位块）
    size_t c_len = ciphertext.size();
    for (size_t offset = 0; offset < c_len; offset += 16) {
        gcm_block c_block = bytes_to_gcm_block(ciphertext, offset);
        state = gcm_xor(state, c_block);
        state = gcm_multiply(state, H);
    }

    // 处理长度块（AAD长度||密文长度，单位：比特）
    gcm_block len_block(aad_len * 8, c_len * 8);
    state = gcm_xor(state, len_block);
    state = gcm_multiply(state, H);

    return state;
}

// CTR模式加密/解密（SM4-CTR）
vector<uint8_t> sm4_ctr(const vector<uint8_t>& input, const vector<uint32_t>& round_keys, gcm_block counter_start) {
    vector<uint8_t> output(input.size());
    size_t num_blocks = (input.size() + 15) / 16;  // 总块数

    for (size_t i = 0; i < num_blocks; ++i) {
        // 加密计数器生成密钥流
        vector<uint8_t> counter_bytes = gcm_block_to_bytes(counter_start);
        vector<uint8_t> keystream = sm4_encrypt_block(counter_bytes, round_keys);

        // 异或得到输出
        size_t offset = i * 16;
        size_t len = min(16ULL, input.size() - offset);
        for (size_t j = 0; j < len; ++j) {
            output[offset + j] = input[offset + j] ^ keystream[j];
        }

        // 计数器递增（低32位，适用于96位Nonce）
        counter_start.lo += 1;
    }

    return output;
}

// 生成初始计数器counter_0（推荐96位Nonce）
gcm_block generate_counter0(const vector<uint8_t>& nonce, const gcm_block& H) {
    if (nonce.size() == 12) {  // 96位Nonce（推荐）
        uint8_t buf[16] = { 0 };
        memcpy(buf, nonce.data(), 12);
        buf[15] = 0x01;  // counter_0 = Nonce || 0x00000001
        return bytes_to_gcm_block(vector<uint8_t>(buf, buf + 16));
    }
    else {  // 非96位Nonce（通过GHASH生成）
        vector<uint8_t> nonce_padded = nonce;
        size_t pad_len = (16 - (nonce.size() % 16)) % 16;
        nonce_padded.insert(nonce_padded.end(), pad_len, 0);

        gcm_block state;
        for (size_t offset = 0; offset < nonce_padded.size(); offset += 16) {
            gcm_block block = bytes_to_gcm_block(nonce_padded, offset);
            state = gcm_xor(state, block);
            state = gcm_multiply(state, H);
        }
        return state;
    }
}

// SM4-GCM加密：返回（密文，标签）
pair<vector<uint8_t>, vector<uint8_t>> sm4_gcm_encrypt(
    const vector<uint8_t>& key,
    const vector<uint8_t>& nonce,
    const vector<uint8_t>& aad,
    const vector<uint8_t>& plaintext,
    size_t tag_len = 16) {

    vector<uint32_t> round_keys = generate_round_keys(key);

    // 哈希密钥H = SM4(全0块)
    vector<uint8_t> zero_block(16, 0);
    gcm_block H = bytes_to_gcm_block(sm4_encrypt_block(zero_block, round_keys));

    // 生成初始计数器counter_0和J0 = SM4(counter_0)
    gcm_block counter0 = generate_counter0(nonce, H);
    vector<uint8_t> J0 = sm4_encrypt_block(gcm_block_to_bytes(counter0), round_keys);

    // CTR加密（从counter0+1开始）
    gcm_block counter_start = counter0;
    counter_start.lo += 1;
    vector<uint8_t> ciphertext = sm4_ctr(plaintext, round_keys, counter_start);

    // 计算标签：Tag = J0 XOR GHASH(AAD, 密文)
    gcm_block S = ghash(H, aad, ciphertext);
    vector<uint8_t> S_bytes = gcm_block_to_bytes(S);
    vector<uint8_t> tag(16);
    for (int i = 0; i < 16; ++i) {
        tag[i] = J0[i] ^ S_bytes[i];
    }
    tag.resize(tag_len);  // 截断标签长度

    return { ciphertext, tag };
}

// SM4-GCM解密：返回明文（验证失败返回空）
vector<uint8_t> sm4_gcm_decrypt(
    const vector<uint8_t>& key,
    const vector<uint8_t>& nonce,
    const vector<uint8_t>& aad,
    const vector<uint8_t>& ciphertext,
    const vector<uint8_t>& tag,
    size_t tag_len = 16) {

    if (tag.size() != tag_len) return {};

    vector<uint32_t> round_keys = generate_round_keys(key);

    // 哈希密钥H = SM4(全0块)
    vector<uint8_t> zero_block(16, 0);
    gcm_block H = bytes_to_gcm_block(sm4_encrypt_block(zero_block, round_keys));

    // 生成初始计数器counter_0和J0 = SM4(counter_0)
    gcm_block counter0 = generate_counter0(nonce, H);
    vector<uint8_t> J0 = sm4_encrypt_block(gcm_block_to_bytes(counter0), round_keys);

    // CTR解密（从counter0+1开始）
    gcm_block counter_start = counter0;
    counter_start.lo += 1;
    vector<uint8_t> plaintext = sm4_ctr(ciphertext, round_keys, counter_start);

    // 验证标签
    gcm_block S = ghash(H, aad, ciphertext);
    vector<uint8_t> S_bytes = gcm_block_to_bytes(S);
    vector<uint8_t> expected_tag(16);
    for (int i = 0; i < 16; ++i) {
        expected_tag[i] = J0[i] ^ S_bytes[i];
    }
    expected_tag.resize(tag_len);

    return (expected_tag == tag) ? plaintext : vector<uint8_t>();
}


// 测试函数
int main() {
    // 测试SM4-GCM
    cout << "=== SM4-GCM 测试 ===" << endl;

    // 生成测试参数
    vector<uint8_t> key = hex_to_bytes(generateRandomHexString(32));  // 128位密钥
    vector<uint8_t> nonce = hex_to_bytes(generateRandomHexString(24)); // 96位Nonce（推荐）
    vector<uint8_t> aad = hex_to_bytes(generateRandomHexString(16));   // 附加数据（16字节）
    vector<uint8_t> plaintext = hex_to_bytes(generateRandomHexString(64)); // 明文（64字节）

    // 加密
    auto start = chrono::high_resolution_clock::now();
    auto [ciphertext, tag] = sm4_gcm_encrypt(key, nonce, aad, plaintext);
    auto end = chrono::high_resolution_clock::now();
    auto enc_time = chrono::duration_cast<chrono::nanoseconds>(end - start).count();

    // 解密
    start = chrono::high_resolution_clock::now();
    vector<uint8_t> decrypted = sm4_gcm_decrypt(key, nonce, aad, ciphertext, tag);
    end = chrono::high_resolution_clock::now();
    auto dec_time = chrono::duration_cast<chrono::nanoseconds>(end - start).count();

    // 输出结果
    cout << "明文: " << bytes_to_hex(plaintext) << endl;
    cout << "密文: " << bytes_to_hex(ciphertext) << endl;
    cout << "标签: " << bytes_to_hex(tag) << endl;
    cout << "加密时间: " << enc_time << " ns" << endl;
    cout << "解密时间: " << dec_time << " ns" << endl;

    // 验证
    if (decrypted == plaintext) {
        cout << "测试结果: 成功（解密一致且标签验证通过）" << endl;
    }
    else {
        cout << "测试结果: 失败" << endl;
    }

    return 0;
}