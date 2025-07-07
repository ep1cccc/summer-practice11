#include <iostream>
#include <vector>
#include <cstdint>
#include <string>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <random>
#include <algorithm>


using namespace std;

// SM4算法参数定义
const int SM4_BLOCK_SIZE = 16;  // 128位块大小
const int SM4_KEY_SIZE = 16;    // 128位密钥大小
const int ROUND_KEY_NUM = 32;   // 轮密钥数量

// S盒
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

// 系统参数FK
static const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

// 固定参数CK
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

// 循环左移函数
uint32_t rotate_left(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// 字节替换函数τ
uint32_t t_1(uint32_t x) {
    uint32_t y = 0;
    y |= (uint32_t)S_BOX[(x >> 24) & 0xFF] << 24;
    y |= (uint32_t)S_BOX[(x >> 16) & 0xFF] << 16;
    y |= (uint32_t)S_BOX[(x >> 8) & 0xFF] << 8;
    y |= (uint32_t)S_BOX[x & 0xFF];
    return y;
}

// 线性变换函数L
uint32_t l_1(uint32_t x) {
    return x ^ rotate_left(x, 2) ^ rotate_left(x, 10) ^ rotate_left(x, 18) ^ rotate_left(x, 24);
}

// 合成置换T
uint32_t t(uint32_t x) {
    return l_1(t_1(x));
}

// 轮密钥生成中的线性变换函数L'
uint32_t l_2(uint32_t x) {
    return x ^ rotate_left(x, 13) ^ rotate_left(x, 23);
}

// 轮密钥生成中的合成置换T'
uint32_t t_(uint32_t x) {
    return l_2(t_1(x));
}

// 生成轮密钥
vector<uint32_t> generate_round_keys(const vector<uint8_t>& key) {
    vector<uint32_t> round_keys(ROUND_KEY_NUM);
    vector<uint32_t> k(4 + ROUND_KEY_NUM);

    // 处理输入密钥
    for (int i = 0; i < 4; i++) {
        k[i] = (key[i * 4] << 24) | (key[i * 4 + 1] << 16) | (key[i * 4 + 2] << 8) | key[i * 4 + 3];
        k[i] ^= FK[i];
    }

    // 生成轮密钥
    for (int i = 0; i < ROUND_KEY_NUM; i++) {
        k[i + 4] = k[i] ^ t_(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]);
        round_keys[i] = k[i + 4];
    }

    return round_keys;
}

// SM4加密单块
vector<uint8_t> sm4_encrypt_block(const vector<uint8_t>& plaintext, const vector<uint32_t>& round_keys) {
    vector<uint8_t> ciphertext(SM4_BLOCK_SIZE);
    vector<uint32_t> x(36);

    // 处理输入明文
    for (int i = 0; i < 4; i++) {
        x[i] = (plaintext[i * 4] << 24) | (plaintext[i * 4 + 1] << 16) | (plaintext[i * 4 + 2] << 8) | plaintext[i * 4 + 3];
    }

    // 32轮迭代
    for (int i = 0; i < 32; i++) {
        x[i + 4] = x[i] ^ t(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ round_keys[i]);
    }

    // 反序输出
    for (int i = 0; i < 4; i++) {
        uint32_t temp = x[35 - i];
        ciphertext[i * 4] = (temp >> 24) & 0xFF;
        ciphertext[i * 4 + 1] = (temp >> 16) & 0xFF;
        ciphertext[i * 4 + 2] = (temp >> 8) & 0xFF;
        ciphertext[i * 4 + 3] = temp & 0xFF;
    }

    return ciphertext;
}

// SM4解密单块
vector<uint8_t> sm4_decrypt_block(const vector<uint8_t>& ciphertext, const vector<uint32_t>& round_keys) {
    // 解密与加密的区别仅在于轮密钥使用顺序相反
    vector<uint32_t> decrypt_round_keys = round_keys;
    reverse(decrypt_round_keys.begin(), decrypt_round_keys.end());
    return sm4_encrypt_block(ciphertext, decrypt_round_keys);
}

// 字节数组转16进制字符串
string bytes_to_hex(const vector<uint8_t>& bytes) {
    stringstream ss;
    ss << hex << setfill('0');
    for (uint8_t b : bytes) {
        ss << setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

// 16进制字符串转字节数组
vector<uint8_t> hex_to_bytes(const string& hex) {
    vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byte_str = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byte_str.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

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
// 测试函数
int main() {
    auto start = chrono::high_resolution_clock::now();
    int size = 20;
    for (int i = 0; i < size; i++) {
        // 测试向量
        string plaintext_hex = generateRandomHexString(32);
        string key_hex = generateRandomHexString(32);

        // 转换为字节数组
        vector<uint8_t> plaintext = hex_to_bytes(plaintext_hex);
        vector<uint8_t> key = hex_to_bytes(key_hex);

        // 生成轮密钥
        vector<uint32_t> round_keys = generate_round_keys(key);

        // 加密
        vector<uint8_t> ciphertext = sm4_encrypt_block(plaintext, round_keys);
        cout << "加密结果: " << bytes_to_hex(ciphertext) << endl;

        // 解密
        vector<uint8_t> decrypted = sm4_decrypt_block(ciphertext, round_keys);
        cout << "解密结果: " << bytes_to_hex(decrypted) << endl;

        // 验证解密结果是否与原文一致
        if (decrypted == plaintext) {
            cout << "解密验证成功!" << endl;
        }
        else {
            cout << "解密验证失败!" << endl;
        }
    }
    auto end = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::microseconds>(end - start).count();

    cout << "代码执行时间: " << duration/size << " 微秒" << endl;

    return 0;
}