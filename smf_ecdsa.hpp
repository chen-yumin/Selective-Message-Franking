#pragma once
#include "symmetric.h"
#include <mcl/fp.hpp>
#include <mcl/ec.hpp>
#include <mcl/ecparam.hpp>
#include <mcl/window_method.hpp>
#include <cybozu/xorshift.hpp>
#include <mcl/gmp_util.hpp>
#include <mcl/ecdsa.hpp>
#include "fe_encode.h"
#include <fstream>
#include <cybozu/stream.hpp>
#include <vector>
#include <cstring>
#include <string>
#include <stdexcept>
#include <memory>
#include <algorithm>
#include <cfloat>
#include <iostream>

typedef mcl::ecdsa::Fp Fp;
typedef mcl::ecdsa::Zn Zn;
typedef mcl::ecdsa::Ec Ec;

static int* BSELECT = nullptr;
void readBytes(uint8_t* buf, size_t size, std::ifstream& is);
const mcl::EcParam& para = mcl::ecparam::secp256k1;

struct Sigma { Zn r; Zn s;};
struct Sig { Zn r; Zn s; uint8_t* seed; Ec w;};
struct Elgamal_cipher { Ec c1; Ec c2; };
struct Srm {
	uint8_t* m;
	uint8_t* kf;
	uint8_t* full_mac;
	int* index;
	Elgamal_cipher c;
};
struct SecretKey { Zn x1; Zn x2; };
struct SecretKeyj { Zn x2; };
struct PublicKeyj { mcl::fp::WindowMethod<Ec> wm_h2; };
struct PublicKey { mcl::fp::WindowMethod<Ec> wm_h1; mcl::fp::WindowMethod<Ec> wm_h2; };
struct KeyPair { SecretKey sk; PublicKey pk; };
struct KeyPairj { SecretKeyj sk; PublicKeyj pk; };
struct State { bool flag; uint8_t estr[580]; };
struct PP { mcl::fp::WindowMethod<Ec> wm_g; };
struct Aux { uint8_t* key; uint8_t* mac; Ec u; };

// 函数声明
void Setup(PP& pp);
KeyPair KG(PP& pp);
KeyPairj KGj(PP& pp);
void Sg(PP& pp, Sig& sig, const unsigned char* msg, Zn& sk, size_t mac_len);
bool Sv(PP& pp, PublicKey& pk, const Sig& sig, const unsigned char* msg, size_t mac_len);
bool Sv(PP& pp, PublicKey& pk, const Sigma& sigma, const unsigned char* msg, size_t mac_len);
long long ns_difference(struct timespec finish, struct timespec start);
void Tg(uint8_t* key, uint8_t* seed, const uint8_t* m_buf, uint8_t* mac);
bool Tv(const Srm& srm);
inline void deriveMaskX1X2(Zn& x1, Zn& x2, const Ec& u);
void Frank(PP& pp, Aux& aux, Sig& sig, SecretKey& sec, PublicKey& pkr, PublicKeyj& pkj, uint8_t* msg);
bool Verify(PP& pp, Aux& aux, Sig& sig, SecretKey& sec, PublicKey& pks, PublicKeyj& pkj, uint8_t* msg);
void Report(Aux& aux, Srm& srm, Sigma& sigma, const uint8_t* msg, const int T[], const Sig& sig, PP& pp, PublicKey& pks, PublicKeyj& pkj, SecretKey& skr);
bool Judge(PP& pp, Aux& aux, SecretKeyj& sec, PublicKey& pks, PublicKey& pkr, const Srm& srm, const Sigma& sigma);
double sum(double *r, int n);
int parse(int argc, char *argv[], int& total_block_num);

inline void Setup(PP& pp) {
	Ec G;
	mcl::initCurve<Ec>(para.curveType, &G);
	pp.wm_g.init(G, 256, 10);
}

inline KeyPair KG(PP& pp) {
	SecretKey sk;
	PublicKey pk;
	sk.x1.setRand(); sk.x2.setRand();
	Ec pub_1, pub_2;
	pp.wm_g.mul(pub_1, sk.x1);
	pp.wm_g.mul(pub_2, sk.x2);
	pk.wm_h1.init(pub_1, 256,10);
	pk.wm_h2.init(pub_2, 256,10);
	return KeyPair {sk, pk};
}

inline KeyPairj KGj(PP& pp) {
	SecretKeyj sk;
	PublicKeyj pk;
	sk.x2.setRand();
	Ec pub_2;
	pp.wm_g.mul(pub_2, sk.x2);
	pk.wm_h2.init(pub_2, 256,10);
	return KeyPairj {sk, pk};
}



inline void deriveMaskX1X2(Zn& x1, Zn& x2, const Ec& u) {
    uint8_t xbuf[32], ybuf[32];
    u.x.serialize(xbuf, 32);
    u.y.serialize(ybuf, 32);
    uint8_t combined[64];
    memcpy(combined, xbuf, 32);
    memcpy(combined+32, ybuf, 32);
    x1.setHashOf(combined, 64);
    uint8_t combined2[65];
    memcpy(combined2, combined, 64);
    combined2[64] = 0x77;
    x2.setHashOf(combined2, 65);
}

inline void Sg(PP& pp, Sig& sig, const unsigned char* msg, Zn& sk, size_t mac_len) {
	
	//std::string m = (const char*)msg;
	std::string m(reinterpret_cast<const char*>(msg), mac_len);  // 完整复制
	Zn r, s;
	Zn z, k;
	Ec Q;
	
	z.setHashOf(m);
	for (;;) {
		k.setRand();
		if (k.isZero()) continue; // 极低概率
		pp.wm_g.mul(Q, k);
		if (Q.isZero()) continue;
		Q.normalize();
		mcl::ecdsa::local::FpToZn(r, Q.x);
		if (r.isZero()) continue;
		Zn::mul(s, r, sk);
		s += z;
		if (s.isZero()) continue;
		s /= k;
		if (s.isNegative()) Zn::neg(s, s);
		sig.r = r;
		sig.s = s;
		return;
	}
}

inline bool Sv(PP& pp, PublicKey& pk, const Sig& sig, const unsigned char* msg, size_t mac_len) {
	Zn r = sig.r;
	Zn s = sig.s;
	if (r.isZero() || s.isZero()) return false;
	if (s.isNegative()) return false;
	//std::string m = (const char*)msg;
	std::string m(reinterpret_cast<const char*>(msg), mac_len);  // 完整复制
	Zn z, w, u1, u2;
	z.setHashOf(m);
	if (s.isZero()) return false;
	Zn::inv(w, s);
	Zn::mul(u1, z, w);
	Zn::mul(u2, r, w);
	Ec Q1, Q2;
	pp.wm_g.mul(Q1, u1);
	pk.wm_h1.mul(Q2, u2);
	Q1 += Q2;
	if (Q1.isZero()) return false;
	Q1.normalize();
	Zn x;
	mcl::ecdsa::local::FpToZn(x, Q1.x);
	return r == x;
}

inline bool Sv(PP& pp, PublicKey& pk, const Sigma& sigma, const unsigned char* msg, size_t mac_len) {
	Zn r = sigma.r;
	Zn s = sigma.s;
	if (r.isZero() || s.isZero()) return false;
	if (s.isNegative()) return false;
	//std::string m = (const char*)msg;
	std::string m(reinterpret_cast<const char*>(msg), mac_len);  // 完整复制
	Zn z, w, u1, u2;
	z.setHashOf(m);
	if (s.isZero()) return false;
	Zn::inv(w, s);
	Zn::mul(u1, z, w);
	Zn::mul(u2, r, w);
	Ec Q1, Q2;
	pp.wm_g.mul(Q1, u1);
	pk.wm_h1.mul(Q2, u2);
	Q1 += Q2;
	if (Q1.isZero()) return false;
	Q1.normalize();
	Zn x;
	mcl::ecdsa::local::FpToZn(x, Q1.x);
	return r == x;
}

inline void Tg(uint8_t* key, uint8_t* seed, const uint8_t* m_buf, uint8_t* mac) {
	uint32_t N = *(uint32_t*)m_buf;
	prg(seed, key, 32*(N+1));
	for (uint32_t i=0; i<N; i++) {
		uint8_t* sub_key = key + i*32;
		const uint8_t* blk_data = nullptr;
		uint32_t blk_len = get_block_from_srm_m(m_buf, i, &blk_data);
		uint8_t* blk_mac = mac + i*32;
		hmac_it(sub_key, blk_data, blk_len, blk_mac);
	}
	uint8_t* meta_key = key + N*32;
	uint32_t meta_len = 4 + N*4;
	uint8_t* meta_tag = mac + N*32;
	hmac_it(meta_key, m_buf, meta_len, meta_tag);
}

inline bool Tv(const Srm& srm) {
	const uint8_t* buf = srm.m;
	uint32_t N_total = *(uint32_t*)buf;
	uint32_t meta_len = 4 + N_total*4;
	const uint8_t* mac = srm.full_mac;
	int t = 0;
	while (srm.index[t] != -1) t++;
	uint8_t* meta_key = (uint8_t*)srm.kf + t*32;
	const uint8_t* meta_tag = mac + N_total*32;
	if (!verify_hmac(meta_key, buf, meta_len, meta_tag)) {
		fprintf(stderr, "Tv fail: m0 meta tag invalid\n");
		return false;
	}

	int j = 0;
	size_t idx_ptr = 0;
	// data_ptr 直接指向原始裸块起始，不再跳过4字节前缀
	const uint8_t* data_ptr = buf + meta_len;

	while (true) {
		int blk_idx = srm.index[idx_ptr++];
		if (blk_idx == -1) break;
		if (blk_idx < 0 || blk_idx >= (int)N_total) return false;

		uint8_t* sub_key = (uint8_t*)srm.kf + j*32;
		// 不再读取本地4字节前缀，从元数据区读取该块标准长度
		uint32_t blk_len = *((uint32_t*)(buf + 4 + blk_idx * 4));
		const uint8_t* ms = data_ptr;
		const uint8_t* tag = mac + blk_idx*32;

		if (!verify_hmac(sub_key, ms, blk_len, tag)) {
			fprintf(stderr, "Tv fail: block %d hmac invalid\n", blk_idx);
			return false;
		}
		// 只偏移块数据长度，不再额外+4
		data_ptr += blk_len;
		j++;
	}
	return true;
}

inline void Frank(PP& pp, Aux& aux, Sig& sig, SecretKey& sec, PublicKey& pkr, PublicKeyj& pkj, uint8_t* msg) {
    RAND_priv_bytes(sig.seed, 32);
    Tg(aux.key, sig.seed, msg, aux.mac);

    // 缓存 pkr.h2 * sec.x2（接收方公钥 h2 分量与发送方私钥 x2 的乘积）
    static Ec base_u;
    static bool base_u_cached = false;
    if (!base_u_cached) {
        pkr.wm_h2.mul(base_u, sec.x2);
        base_u_cached = true;
    }

    // 生成随机点 mask_u
    Ec mask_u;
    Zn r;
    r.setRand();
    pp.wm_g.mul(mask_u, r);

    // u = base_u + mask_u
    Ec u = base_u;
    Ec::add(u, u, mask_u);
    u.normalize();
    u.normalize();
    if (u.isZero()) {
        fprintf(stderr, "Error: ec point u is zero!\n");
        exit(EXIT_FAILURE);
    }
    u.normalize();

    uint32_t N = *(uint32_t*)msg;
    Sg(pp, sig, aux.mac, sec.x1, (N + 1) * 32);

    Zn x1, x2;
    deriveMaskX1X2(x1, x2, u);

    sig.r = sig.r + x1;
    sig.s = sig.s + x2;
    sig.w = mask_u;   // 保存随机点用于 Verify/Report
}



inline bool Verify(PP& pp, Aux& aux, Sig& sig, SecretKey& sec, PublicKey& pks, PublicKeyj& pkj, uint8_t* msg) {
    Tg(aux.key, sig.seed, msg, aux.mac);

    // 缓存 pks.h2 * sec.x2（发送方公钥 h2 分量与接收方私钥 x2 的乘积）
    static Ec base_v;
    static bool base_v_cached = false;
    if (!base_v_cached) {
        pks.wm_h2.mul(base_v, sec.x2);
        base_v_cached = true;
    }

    // u = base_v + sig.w（sig.w 是 Frank 传递的随机点）
    Ec u = base_v;
    Ec::add(u, u, sig.w);
    u.normalize();
    u.normalize();
    if (u.isZero()) {
        fprintf(stderr, "Verify u zero point\n");
        exit(EXIT_FAILURE);
    }

    Zn x1, x2;
    deriveMaskX1X2(x1, x2, u);

    Zn raw_r = sig.r - x1;
    Zn raw_s = sig.s - x2;

    Sig tmp_sig;
    tmp_sig.r = raw_r;
    tmp_sig.s = raw_s;
    tmp_sig.seed = sig.seed;
    tmp_sig.w = sig.w;
    uint32_t N = *(uint32_t*)msg;

    return Sv(pp, pks, tmp_sig, aux.mac, (N + 1) * 32);
}

inline void Report(Aux& aux, Srm& srm, Sigma& sigma, const uint8_t* msg,
        const int T[], const Sig& sig, PP& pp, PublicKey& pks, PublicKeyj& pkj, SecretKey& skr) {
    // 使用 Frank 已生成的 aux.mac（不重复计算）
    srm.full_mac = aux.mac;

    int h = 0;
    uint32_t N_total = *(uint32_t*)msg;
    uint32_t meta_len = 4 + N_total * 4;
    const uint32_t* lens = (const uint32_t*)(msg + 4);   // 长度表
    uint32_t data_start = meta_len;                       // 数据区起始偏移

    // 缓存 pks.h2 * skr.x2（发送方公钥 h2 分量与接收方私钥 x2 的乘积）
    static Ec base_r;
    static bool base_r_cached = false;
    if (!base_r_cached) {
        pks.wm_h2.mul(base_r, skr.x2);
        base_r_cached = true;
    }

    aux.u = base_r;
    Ec::add(aux.u, aux.u, sig.w);
    aux.u.normalize();

    // ElGamal 加密
    Ec c1, c2;
    Zn r;
    r.setRand();
    pp.wm_g.mul(c1, r);
    c1.normalize();
    pkj.wm_h2.mul(c2, r);
    Ec::add(c2, c2, aux.u);
    c2.normalize();

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
            memmove(ptr, blk_data, blk_len);
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

    sigma.r = sig.r;
    sigma.s = sig.s;
    srm.c.c1 = c1;
    srm.c.c2 = c2;
}

//inline void Report(Aux& aux, Srm& srm, Sigma& sigma, const uint8_t* msg,
        //const int T[], const Sig& sig, PP& pp, PublicKey& pks, PublicKeyj& pkj, SecretKey& skr) {
    //// 直接使用 Frank 已生成的 aux.mac（避免重复 Tg）
    //// （注意：若您需要重新生成，可取消注释，但为性能优化，此处沿用）
    //Tg(aux.key, sig.seed, msg, srm.full_mac);

    //int h = 0;

    //// 缓存 pks.h2 * skr.x2（发送方公钥 h2 分量与接收方私钥 x2 的乘积）
    //static Ec base_r;
    //static bool base_r_cached = false;
    //if (!base_r_cached) {
        //pks.wm_h2.mul(base_r, skr.x2);
        //base_r_cached = true;
    //}

    //// aux.u = base_r + sig.w
    //aux.u = base_r;
    //Ec::add(aux.u, aux.u, sig.w);
    //aux.u.normalize();
    //aux.u.normalize();

    //Ec c1, c2;
    //Zn r;
    //r.setRand();
    //pp.wm_g.mul(c1, r);
    //c1.normalize();
    //c1.normalize();
    //pkj.wm_h2.mul(c2, r);
    //Ec::add(c2, c2, aux.u);
    //c2.normalize();
    //c2.normalize();

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

    //sigma.r = sig.r;
    //sigma.s = sig.s;
    //srm.c.c1 = c1;
    //srm.c.c2 = c2;
//}


inline bool Judge(PP& pp, Aux& aux, SecretKeyj& sec, PublicKey& pks, PublicKey& pkr,
        const Srm& srm, const Sigma& sigma) {
    if (!Tv(srm)) return false;

    Ec u, c1 = srm.c.c1;
    c1.normalize();
    Ec::mul(c1, c1, sec.x2);
    Ec::sub(u, srm.c.c2, c1);
    if (u.isZero()) return false;
    u.normalize();

    Zn x1, x2;
    deriveMaskX1X2(x1, x2, u);
    

    Zn raw_r = sigma.r - x1;
    Zn raw_s = sigma.s - x2;
    Sigma tmp_sigma;
    tmp_sigma.r = raw_r;
    tmp_sigma.s = raw_s;
    uint32_t N = *(uint32_t*)srm.m;

    return Sv(pp, pks, tmp_sigma, srm.full_mac, (N+1)*32);
}

inline long long ns_difference(struct timespec finish, struct timespec start) {
	return (finish.tv_sec - start.tv_sec) * 1000000000LL + (finish.tv_nsec - start.tv_nsec);
}

inline double sum(double *r, int n) {
	double res = 0;
	for (int i=0; i<n; i++) res += r[i];
	return res;
}

inline int parse(int argc, char *argv[], int& total_block_num) {
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

	for (int i=0; i<t; i++) {
		int idx = atoi(argv[2+i]);
		if (idx < 0 || idx >= total_block_num) {
			fprintf(stderr, "Index %d out of range [0, %d]\n", idx, total_block_num-1);
			delete[] BSELECT;
			BSELECT = nullptr;
			exit(1);
		}
		BSELECT[i] = idx;
	}
	BSELECT[t] = -1;
	return t;
}


