#pragma once
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <fstream>
#include <vector>
#include <algorithm>
#include <stdexcept>
#include <memory>

#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <err.h>

#include <mcl/bls12_381.hpp>
#include <mcl/fp.hpp>
#include <mcl/ec.hpp>
#include <mcl/ecparam.hpp>
#include <mcl/window_method.hpp>
#include <cybozu/xorshift.hpp>
#include <mcl/gmp_util.hpp>
#include <mcl/ecdsa.hpp>
#include <cybozu/stream.hpp>

#include "symmetric.h"
#include "fe_encode.h"

using namespace mcl::bn;

// ========== 类型别名 ==========
typedef G1 G1;
typedef G2 G2;
typedef Fp12 Fp12;
typedef Fp Fp;
typedef Fr Fr;

// ========== 全局变量 ==========
static int* BSELECT = nullptr;
static mcl::fp::WindowMethod<G1> g1_window;   // 用于快速固定基乘法

// ========== 数据结构 ==========
struct Sigma {
    G1 sgn;
};

struct Sig {
    G1 sgn;
    uint8_t* seed;
    Fr w;
};

struct Srm {
    uint8_t* m;
    uint8_t* kf;
    uint8_t* full_mac;
    int* index;
    G1 mask_w;
};

struct PP {
    G2 G;
    G1 G_1;
};

struct Aux {
    uint8_t* key;
    uint8_t* mac;
};

struct SecretKey {
    Fr x;
};

struct PublicKey {
    G1 h1;
    G2 h2;
};

struct KeyPair {
    SecretKey sk;
    PublicKey pk;
};

// ========== 辅助函数 ==========
void readBytes(uint8_t* buf, size_t size, std::ifstream& is) {
    cybozu::readSome(buf, size, is);
    buf[size] = '\0';
}

// 从 Fp12 u 派生 Fr 掩码（使用 getStr() 确保确定性）
inline void deriveFrMask(Fr& mask, const Fp12& u) {
    std::string s = u.getStr();
    mask.setHashOf(s.c_str(), s.size());
}

// ========== 协议函数 ==========
void Setup(PP& pp) {
    initPairing(mcl::BLS12_381);
    mapToG2(pp.G, 1);
    mapToG1(pp.G_1, 1);
    // 初始化窗口方法加速固定基乘法
    g1_window.init(pp.G_1, 256, 10);
}

KeyPair KG(PP& pp) {
    SecretKey sk;
    PublicKey pk;
    sk.x.setRand();
    G1::mul(pk.h1, pp.G_1, sk.x);
    G2::mul(pk.h2, pp.G, sk.x);
    return KeyPair{sk, pk};
}

void Sg(PP& pp, Sig& sig, const unsigned char* msg, Fr& sk, size_t mac_len) {
    std::string m(reinterpret_cast<const char*>(msg), mac_len);
    Fp t;
    t.setHashOf(m);
    G1 Hm;
    mapToG1(Hm, t);
    G1::mul(sig.sgn, Hm, sk);
}

bool Sv(PP& pp, PublicKey& pk, const Sig& sig, const unsigned char* msg, size_t mac_len) {
    std::string m(reinterpret_cast<const char*>(msg), mac_len);
    Fp12 e1, e2;
    G1 Hm;
    Fp t;
    t.setHashOf(m);
    mapToG1(Hm, t);
    Hm.normalize();

    G1 sgn = sig.sgn;
    sgn.normalize();

    pairing(e1, sgn, pp.G);
    pairing(e2, Hm, pk.h2);
    return e1 == e2;
}

bool Sv(PP& pp, PublicKey& pk, const Sigma& sigma, const unsigned char* msg, size_t mac_len) {
    std::string m(reinterpret_cast<const char*>(msg), mac_len);
    Fp12 e1, e2;
    G1 Hm;
    Fp t;
    t.setHashOf(m);
    mapToG1(Hm, t);
    Hm.normalize();

    G1 sgn = sigma.sgn;
    sgn.normalize();

    pairing(e1, sgn, pp.G);
    pairing(e2, Hm, pk.h2);
    return e1 == e2;
}

long long ns_difference(struct timespec finish, struct timespec start) {
    long long NS_PER_SECOND = 1000000000;
    long long nsec_diff = finish.tv_nsec - start.tv_nsec;
    long long sec_diff = finish.tv_sec - start.tv_sec;
    return nsec_diff + sec_diff * NS_PER_SECOND;
}

inline void Tg(uint8_t* key, uint8_t* seed, const uint8_t* m_buf, uint8_t* mac) {
    uint32_t N = *(uint32_t*)m_buf;
    prg(seed, key, 32 * (N + 1));
    for (uint32_t i = 0; i < N; ++i) {
        uint8_t* sub_key = key + i * 32;
        const uint8_t* blk_data = nullptr;
        uint32_t blk_len = get_block_from_srm_m(m_buf, i, &blk_data);
        uint8_t* blk_mac = mac + i * 32;
        hmac_it(sub_key, blk_data, blk_len, blk_mac);
    }
    uint8_t* meta_key = key + N * 32;
    uint32_t meta_len = 4 + N * 4;
    uint8_t* meta_tag = mac + N * 32;
    hmac_it(meta_key, m_buf, meta_len, meta_tag);
}

inline bool Tv(const Srm& srm) {
    const uint8_t* buf = srm.m;
    uint32_t N_total = *(uint32_t*)buf;
    uint32_t meta_len = 4 + N_total * 4;
    const uint8_t* mac = srm.full_mac;
    int t = 0;
    while (srm.index[t] != -1) ++t;
    uint8_t* meta_key = (uint8_t*)srm.kf + t * 32;
    const uint8_t* meta_tag = mac + N_total * 32;
    if (!verify_hmac(meta_key, buf, meta_len, meta_tag)) {
        fprintf(stderr, "Tv fail: m0 meta tag invalid\n");
        return false;
    }

    int j = 0;
    size_t idx_ptr = 0;
    const uint8_t* data_ptr = buf + meta_len;
    while (true) {
        int blk_idx = srm.index[idx_ptr++];
        if (blk_idx == -1) break;
        if (blk_idx < 0 || blk_idx >= (int)N_total) return false;

        uint8_t* sub_key = (uint8_t*)srm.kf + j * 32;
        uint32_t blk_len = *((uint32_t*)(buf + 4 + blk_idx * 4));
        const uint8_t* ms = data_ptr;
        const uint8_t* tag = mac + blk_idx * 32;

        if (!verify_hmac(sub_key, ms, blk_len, tag)) {
            fprintf(stderr, "Tv fail: block %d hmac invalid\n", blk_idx);
            return false;
        }
        data_ptr += blk_len;
        ++j;
    }
    return true;
}

// ========== Frank ==========
void Frank(PP& pp, Aux& aux, Sig& sig, SecretKey& sec, PublicKey& pkr,
           PublicKey& pkj, uint8_t* msg) {
    RAND_priv_bytes(sig.seed, 32);
    Tg(aux.key, sig.seed, msg, aux.mac);

    // 计算 u（用于掩码派生）
    Fp12 u;
    sig.w.setRand();
    G1 mask_w;
    g1_window.mul(mask_w, sig.w);          // 优化：使用窗口方法
    G1::add(mask_w, mask_w, pkr.h1);
    pairing(u, mask_w, pkj.h2);
    Fp12::pow(u, u, sec.x);

    uint32_t N = *(uint32_t*)msg;
    // 生成原始签名
    Sg(pp, sig, aux.mac, sec.x, (N + 1) * 32);
    sig.sgn.normalize();

    // 混淆：sig.sgn += w * G_1  （使用 g1_window）
    G1 wG;
    Fr wr;
    deriveFrMask(wr, u);
    g1_window.mul(wG, wr);            // 优化：窗口方法
    G1::add(sig.sgn, sig.sgn, wG);
    sig.sgn.normalize();
}

// ========== Verify ==========
bool Verify(PP& pp, Aux& aux, Sig& sig, SecretKey& sec, PublicKey& pks,
            PublicKey& pkj, uint8_t* msg) {
    Tg(aux.key, sig.seed, msg, aux.mac);

    Fp12 u;
    pairing(u, pks.h1, pkj.h2);
    Fr tmp_x = sec.x + sig.w;
    Fp12::pow(u, u, tmp_x);

    Fr mask;
    deriveFrMask(mask, u);

    // 还原签名：raw = sig.sgn - mask * G_1
    G1 maskG;
    g1_window.mul(maskG, mask);           // 优化：窗口方法
    G1 raw_sgn;
    G1::sub(raw_sgn, sig.sgn, maskG);
    raw_sgn.normalize();

    Sig tmp_sig;
    tmp_sig.sgn = raw_sgn;
    tmp_sig.seed = sig.seed;
    uint32_t N = *(uint32_t*)msg;
    return Sv(pp, pks, tmp_sig, aux.mac, (N + 1) * 32);
}

inline void Report(Aux& aux, Srm& srm, Sigma& sigma, const uint8_t* msg,
        const int T[], const Sig& sig, PP& pp) {
    // 使用 Frank 已生成的 aux.mac（不重复计算）
    srm.full_mac = aux.mac;
    
    sigma.sgn = sig.sgn;
    sigma.sgn.normalize();
    g1_window.mul(srm.mask_w, sig.w);     // 优化：窗口方法

    int h = 0;
    uint32_t N_total = *(uint32_t*)msg;
    uint32_t meta_len = 4 + N_total * 4;
    const uint32_t* lens = (const uint32_t*)(msg + 4);   // 长度表
    uint32_t data_start = meta_len;                       // 数据区起始偏移


    // 拷贝头部到 srm.m
    uint8_t* ptr = srm.m;
    memcpy(ptr, msg, meta_len);
    ptr += meta_len;

    // 按 T 顺序处理上报块
    int t = 0;
    while (true) {
        int blk_idx = T[t++];
        if (blk_idx == -1) break;
        if (blk_idx < 0 || blk_idx >= (int)N_total || h >= (int)N_total) break;

        // 直接从长度表计算偏移（无需函数调用）
        uint32_t offset = 0;
        for (int i = 0; i < blk_idx; ++i) offset += lens[i];
        const uint8_t* blk_data = msg + data_start + offset;
        uint32_t blk_len = lens[blk_idx];

        srm.index[h] = blk_idx;
        for (int j = 0; j < 32; ++j)
            srm.kf[h * 32 + j] = aux.key[blk_idx * 32 + j];

        // 直接拷贝裸块数据（无长度前缀）
        if (blk_data && blk_len > 0) {
            memcpy(ptr, blk_data, blk_len);
            ptr += blk_len;
        }
        ++h;
    }

    // 元数据密钥
    for (int j = 0; j < 32; ++j)
        srm.kf[h * 32 + j] = aux.key[N_total * 32 + j];
    srm.index[h] = -1;

    // 拷贝 full_mac（由 Frank 生成）
    //size_t mac_total_len = (size_t)N_total * 32 + 32;
    //memcpy(srm.full_mac, aux.mac, mac_total_len);

    
}

// ========== Report ==========
//void Report(Aux& aux, Srm& srm, Sigma& sigma, const uint8_t* msg,
            //const int T[], const Sig& sig, PP& pp) {
    //Tg(aux.key, sig.seed, msg, srm.full_mac);

    //sigma.sgn = sig.sgn;
    //sigma.sgn.normalize();
    //g1_window.mul(srm.mask_w, sig.w);     // 优化：窗口方法

    //int h = 0;
    //int t = 0;
    //uint32_t N_total = *(uint32_t*)msg;
    //uint32_t meta_len = 4 + N_total * 4;

    //uint8_t* ptr = srm.m;
    //memcpy(ptr, msg, meta_len);
    //ptr += meta_len;

    //while (true) {
        //int blk_idx = T[t++];
        //if (blk_idx == -1) break;
        //if (blk_idx < 0 || blk_idx >= (int)N_total || h >= (int)N_total) break;
        //srm.index[h] = blk_idx;
        //for (int j = 0; j < 32; ++j)
            //srm.kf[h * 32 + j] = aux.key[blk_idx * 32 + j];

        //const uint8_t* blk_data = nullptr;
        //uint32_t blk_len = get_block_from_srm_m(msg, blk_idx, &blk_data);
        //if (blk_data && blk_len > 0) {
            //memcpy(ptr, blk_data, blk_len);
            //ptr += blk_len;
        //}
        //++h;
    //}
    //for (int j = 0; j < 32; ++j)
        //srm.kf[h * 32 + j] = aux.key[N_total * 32 + j];
    //srm.index[h] = -1;

    ////size_t mac_total_len = (size_t)N_total * 32 + 32;
    ////memcpy(srm.full_mac, aux.mac, mac_total_len);
//}

// ========== Judge ==========
bool Judge(PP& pp, Aux& aux, SecretKey& sec, PublicKey& pks, PublicKey& pkr,
           const Srm& srm, const Sigma& sigma) {
    if (!Tv(srm)) return false;

    Fp12 u;
    G1 tmp_pkr;
    G1::add(tmp_pkr, pkr.h1, srm.mask_w);
    pairing(u, tmp_pkr, pks.h2);
    Fp12::pow(u, u, sec.x);

    Fr mask;
    deriveFrMask(mask, u);

    // 还原签名：raw = sigma.sgn - mask * G_1
    G1 maskG;
    g1_window.mul(maskG, mask);           // 优化：窗口方法
    G1 raw_sgn;
    G1::sub(raw_sgn, sigma.sgn, maskG);
    raw_sgn.normalize();

    Sigma tmp_sigma;
    tmp_sigma.sgn = raw_sgn;
    uint32_t N = *(uint32_t*)srm.m;
    return Sv(pp, pks, tmp_sigma, srm.full_mac, (N + 1) * 32);
}

// ========== 辅助工具 ==========
double sum(double* r, int n) {
    double s = 0;
    for (int i = 0; i < n; ++i) s += r[i];
    return s / (n * 1000);
}

inline int parse(int argc, char* argv[], int& total_block_num) {
    if (argc < 2) {
        fprintf(stderr, "Usage: ./smf_test N idx1 idx2 ...\n");
        exit(EXIT_FAILURE);
    }
    total_block_num = atoi(argv[1]);
    if (total_block_num <= 0) {
        fprintf(stderr, "N must > 0\n");
        exit(1);
    }
    int t = argc - 2;
    if (t < 0) t = 0;

    if (BSELECT != nullptr) {
        delete[] BSELECT;
        BSELECT = nullptr;
    }
    BSELECT = new int[total_block_num + 2];
    std::fill_n(BSELECT, total_block_num + 2, -1);

    for (int i = 0; i < t; ++i) {
        int idx = atoi(argv[2 + i]);
        if (idx < 0 || idx >= total_block_num) {
            fprintf(stderr, "Index %d out of range [0, %d]\n", idx, total_block_num - 1);
            delete[] BSELECT;
            BSELECT = nullptr;
            exit(1);
        }
        BSELECT[i] = idx;
    }
    BSELECT[t] = -1;
    return t;
}
