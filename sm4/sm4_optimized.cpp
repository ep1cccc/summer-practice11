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

// SM4�㷨�������壨����ԭSM4ʵ�֣�
const int SM4_BLOCK_SIZE = 16;  // 128λ���С
const int SM4_KEY_SIZE = 16;    // 128λ��Կ��С
const int ROUND_KEY_NUM = 32;   // ����Կ����

// S�У����ã�
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

// ϵͳ����FK�����ã�
static const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

// �̶�����CK�����ã�
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

// ѭ�����ƺ��������ã�
uint32_t rotate_left(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// �ֽ��滻�����ӣ����ã�
uint32_t t_1(uint32_t x) {
    uint32_t y = 0;
    y |= (uint32_t)S_BOX[(x >> 24) & 0xFF] << 24;
    y |= (uint32_t)S_BOX[(x >> 16) & 0xFF] << 16;
    y |= (uint32_t)S_BOX[(x >> 8) & 0xFF] << 8;
    y |= (uint32_t)S_BOX[x & 0xFF];
    return y;
}

// ���Ա任����L�����ã�
uint32_t l_1(uint32_t x) {
    return x ^ rotate_left(x, 2) ^ rotate_left(x, 10) ^ rotate_left(x, 18) ^ rotate_left(x, 24);
}

// �ϳ��û�T�����ã�
uint32_t t(uint32_t x) {
    return l_1(t_1(x));
}

// ����Կ�����е����Ա任����L'�����ã�
uint32_t l_2(uint32_t x) {
    return x ^ rotate_left(x, 13) ^ rotate_left(x, 23);
}

// ����Կ�����еĺϳ��û�T'�����ã�
uint32_t t_(uint32_t x) {
    return l_2(t_1(x));
}

// ��������Կ�����ã�
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

// SM4���ܵ��飨���ã�
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

// �ֽ�����ת16�����ַ��������ã�
string bytes_to_hex(const vector<uint8_t>& bytes) {
    stringstream ss;
    ss << hex << setfill('0');
    for (uint8_t b : bytes) {
        ss << setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

// 16�����ַ���ת�ֽ����飨���ã�
vector<uint8_t> hex_to_bytes(const string& hex) {
    vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        string byte_str = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byte_str.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// �������16�����ַ��������ã�
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


// ---------------------- GCMģʽʵ�� ----------------------

// ����128λ�飨����GF(2^128)���㣩
struct gcm_block {
    uint64_t hi;  // ��64λ
    uint64_t lo;  // ��64λ

    gcm_block() : hi(0), lo(0) {}
    gcm_block(uint64_t h, uint64_t l) : hi(h), lo(l) {}
};

// ����128λ�����
gcm_block gcm_xor(const gcm_block& a, const gcm_block& b) {
    return gcm_block(a.hi ^ b.hi, a.lo ^ b.lo);
}

// 128λ������1λ��������Լ����ʽx^128 + x^7 + x^2 + x + 1Լ��
gcm_block gcm_shift_left1(const gcm_block& x) {
    gcm_block res;
    res.hi = (x.hi << 1) | (x.lo >> 63);  // ��64λ���ƣ���64λ���λ����
    res.lo = x.lo << 1;                    // ��64λ����

    // ��ԭ���λΪ1�����Լ�����ʽ��0x87��
    if (x.hi & (1ULL << 63)) {
        res.lo ^= 0x87;
    }
    return res;
}

// GF(2^128)�˷����Ż��棺��8λ���鴦������ѭ��������
gcm_block gcm_multiply(const gcm_block& a, const gcm_block& b) {
    gcm_block res;
    gcm_block temp = a;

    // Ԥ����a����0-7λ�Ľ������Լ��
    gcm_block shifts[8];
    shifts[0] = a;
    for (int i = 1; i < 8; ++i) {
        shifts[i] = gcm_shift_left1(shifts[i - 1]);
    }

    // �����64λ��8���8λ��
    for (int i = 0; i < 8; ++i) {
        uint8_t byte = (b.lo >> (i * 8)) & 0xFF;
        for (int j = 0; j < 8; ++j) {
            if (byte & (1 << j)) {
                res = gcm_xor(res, shifts[(i * 8 + j) % 8]);
            }
        }
        temp = shifts[7];  // ����8λ������Ԥ��������
    }

    // �����64λ��8���8λ��
    for (int i = 0; i < 8; ++i) {
        uint8_t byte = (b.hi >> (i * 8)) & 0xFF;
        for (int j = 0; j < 8; ++j) {
            if (byte & (1 << j)) {
                gcm_block shift = a;
                // ����64 + i*8 + jλ���Ż���ѭ��չ����
                for (int k = 0; k < 64 + i * 8 + j; ++k) {
                    shift = gcm_shift_left1(shift);
                }
                res = gcm_xor(res, shift);
            }
        }
    }

    return res;
}

// �ֽ�����ת128λ�飨�����
gcm_block bytes_to_gcm_block(const vector<uint8_t>& bytes, size_t offset = 0) {
    gcm_block block;
    uint8_t buf[16] = { 0 };
    size_t len = min(16ULL, bytes.size() - offset);
    memcpy(buf, &bytes[offset], len);

    // ��64λ��ǰ8�ֽڣ�
    block.hi = 0;
    for (int i = 0; i < 8; ++i) {
        block.hi = (block.hi << 8) | buf[i];
    }
    // ��64λ����8�ֽڣ�
    block.lo = 0;
    for (int i = 8; i < 16; ++i) {
        block.lo = (block.lo << 8) | buf[i];
    }
    return block;
}

// 128λ��ת�ֽ����飨�����
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

// GHASH������������֤��ǩ�ĺ��ģ�AAD�����ĵĹ�ϣ��
gcm_block ghash(const gcm_block& H, const vector<uint8_t>& AAD, const vector<uint8_t>& ciphertext) {
    gcm_block state;  // ��ʼΪ0

    // ����AAD����128λ�飩
    size_t aad_len = AAD.size();
    for (size_t offset = 0; offset < aad_len; offset += 16) {
        gcm_block a_block = bytes_to_gcm_block(AAD, offset);
        state = gcm_xor(state, a_block);
        state = gcm_multiply(state, H);
    }

    // �������ģ���128λ�飩
    size_t c_len = ciphertext.size();
    for (size_t offset = 0; offset < c_len; offset += 16) {
        gcm_block c_block = bytes_to_gcm_block(ciphertext, offset);
        state = gcm_xor(state, c_block);
        state = gcm_multiply(state, H);
    }

    // �����ȿ飨AAD����||���ĳ��ȣ���λ�����أ�
    gcm_block len_block(aad_len * 8, c_len * 8);
    state = gcm_xor(state, len_block);
    state = gcm_multiply(state, H);

    return state;
}

// CTRģʽ����/���ܣ�SM4-CTR��
vector<uint8_t> sm4_ctr(const vector<uint8_t>& input, const vector<uint32_t>& round_keys, gcm_block counter_start) {
    vector<uint8_t> output(input.size());
    size_t num_blocks = (input.size() + 15) / 16;  // �ܿ���

    for (size_t i = 0; i < num_blocks; ++i) {
        // ���ܼ�����������Կ��
        vector<uint8_t> counter_bytes = gcm_block_to_bytes(counter_start);
        vector<uint8_t> keystream = sm4_encrypt_block(counter_bytes, round_keys);

        // ���õ����
        size_t offset = i * 16;
        size_t len = min(16ULL, input.size() - offset);
        for (size_t j = 0; j < len; ++j) {
            output[offset + j] = input[offset + j] ^ keystream[j];
        }

        // ��������������32λ��������96λNonce��
        counter_start.lo += 1;
    }

    return output;
}

// ���ɳ�ʼ������counter_0���Ƽ�96λNonce��
gcm_block generate_counter0(const vector<uint8_t>& nonce, const gcm_block& H) {
    if (nonce.size() == 12) {  // 96λNonce���Ƽ���
        uint8_t buf[16] = { 0 };
        memcpy(buf, nonce.data(), 12);
        buf[15] = 0x01;  // counter_0 = Nonce || 0x00000001
        return bytes_to_gcm_block(vector<uint8_t>(buf, buf + 16));
    }
    else {  // ��96λNonce��ͨ��GHASH���ɣ�
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

// SM4-GCM���ܣ����أ����ģ���ǩ��
pair<vector<uint8_t>, vector<uint8_t>> sm4_gcm_encrypt(
    const vector<uint8_t>& key,
    const vector<uint8_t>& nonce,
    const vector<uint8_t>& aad,
    const vector<uint8_t>& plaintext,
    size_t tag_len = 16) {

    vector<uint32_t> round_keys = generate_round_keys(key);

    // ��ϣ��ԿH = SM4(ȫ0��)
    vector<uint8_t> zero_block(16, 0);
    gcm_block H = bytes_to_gcm_block(sm4_encrypt_block(zero_block, round_keys));

    // ���ɳ�ʼ������counter_0��J0 = SM4(counter_0)
    gcm_block counter0 = generate_counter0(nonce, H);
    vector<uint8_t> J0 = sm4_encrypt_block(gcm_block_to_bytes(counter0), round_keys);

    // CTR���ܣ���counter0+1��ʼ��
    gcm_block counter_start = counter0;
    counter_start.lo += 1;
    vector<uint8_t> ciphertext = sm4_ctr(plaintext, round_keys, counter_start);

    // �����ǩ��Tag = J0 XOR GHASH(AAD, ����)
    gcm_block S = ghash(H, aad, ciphertext);
    vector<uint8_t> S_bytes = gcm_block_to_bytes(S);
    vector<uint8_t> tag(16);
    for (int i = 0; i < 16; ++i) {
        tag[i] = J0[i] ^ S_bytes[i];
    }
    tag.resize(tag_len);  // �ضϱ�ǩ����

    return { ciphertext, tag };
}

// SM4-GCM���ܣ��������ģ���֤ʧ�ܷ��ؿգ�
vector<uint8_t> sm4_gcm_decrypt(
    const vector<uint8_t>& key,
    const vector<uint8_t>& nonce,
    const vector<uint8_t>& aad,
    const vector<uint8_t>& ciphertext,
    const vector<uint8_t>& tag,
    size_t tag_len = 16) {

    if (tag.size() != tag_len) return {};

    vector<uint32_t> round_keys = generate_round_keys(key);

    // ��ϣ��ԿH = SM4(ȫ0��)
    vector<uint8_t> zero_block(16, 0);
    gcm_block H = bytes_to_gcm_block(sm4_encrypt_block(zero_block, round_keys));

    // ���ɳ�ʼ������counter_0��J0 = SM4(counter_0)
    gcm_block counter0 = generate_counter0(nonce, H);
    vector<uint8_t> J0 = sm4_encrypt_block(gcm_block_to_bytes(counter0), round_keys);

    // CTR���ܣ���counter0+1��ʼ��
    gcm_block counter_start = counter0;
    counter_start.lo += 1;
    vector<uint8_t> plaintext = sm4_ctr(ciphertext, round_keys, counter_start);

    // ��֤��ǩ
    gcm_block S = ghash(H, aad, ciphertext);
    vector<uint8_t> S_bytes = gcm_block_to_bytes(S);
    vector<uint8_t> expected_tag(16);
    for (int i = 0; i < 16; ++i) {
        expected_tag[i] = J0[i] ^ S_bytes[i];
    }
    expected_tag.resize(tag_len);

    return (expected_tag == tag) ? plaintext : vector<uint8_t>();
}


// ���Ժ���
int main() {
    // ����SM4-GCM
    cout << "=== SM4-GCM ���� ===" << endl;

    // ���ɲ��Բ���
    vector<uint8_t> key = hex_to_bytes(generateRandomHexString(32));  // 128λ��Կ
    vector<uint8_t> nonce = hex_to_bytes(generateRandomHexString(24)); // 96λNonce���Ƽ���
    vector<uint8_t> aad = hex_to_bytes(generateRandomHexString(16));   // �������ݣ�16�ֽڣ�
    vector<uint8_t> plaintext = hex_to_bytes(generateRandomHexString(64)); // ���ģ�64�ֽڣ�

    // ����
    auto start = chrono::high_resolution_clock::now();
    auto [ciphertext, tag] = sm4_gcm_encrypt(key, nonce, aad, plaintext);
    auto end = chrono::high_resolution_clock::now();
    auto enc_time = chrono::duration_cast<chrono::nanoseconds>(end - start).count();

    // ����
    start = chrono::high_resolution_clock::now();
    vector<uint8_t> decrypted = sm4_gcm_decrypt(key, nonce, aad, ciphertext, tag);
    end = chrono::high_resolution_clock::now();
    auto dec_time = chrono::duration_cast<chrono::nanoseconds>(end - start).count();

    // ������
    cout << "����: " << bytes_to_hex(plaintext) << endl;
    cout << "����: " << bytes_to_hex(ciphertext) << endl;
    cout << "��ǩ: " << bytes_to_hex(tag) << endl;
    cout << "����ʱ��: " << enc_time << " ns" << endl;
    cout << "����ʱ��: " << dec_time << " ns" << endl;

    // ��֤
    if (decrypted == plaintext) {
        cout << "���Խ��: �ɹ�������һ���ұ�ǩ��֤ͨ����" << endl;
    }
    else {
        cout << "���Խ��: ʧ��" << endl;
    }

    return 0;
}