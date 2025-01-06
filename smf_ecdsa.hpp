#include <stdio.h>
#include "symmetric.h"
#include <string.h>
#include <stdint.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <err.h>
#include <time.h>
#include <math.h>

#include <mcl/bls12_381.hpp>
#include <mcl/fp.hpp>
#include <mcl/ec.hpp>
#include <mcl/ecparam.hpp>
#include <mcl/window_method.hpp>
#include <cybozu/xorshift.hpp>
#include <mcl/gmp_util.hpp>
#include <mcl/ecdsa.hpp>


#include <fstream>
#include <cybozu/stream.hpp>
//using std::begin; using std::end;
//using namespace mcl::bn;
//bn　中已有对Fp, Fr 定义，故不能再用模板

//typedef mcl::FpT<> Fp;
//struct tagZn;
//typedef mcl::FpT<tagZn> Zn;
//typedef mcl::bn::Fr Zn;
//typedef mcl::EcT<Fp, Zn> Ec;

typedef mcl::ecdsa::Fp Fp;
typedef mcl::ecdsa::Zn Zn;
typedef mcl::ecdsa::Ec Ec;
typedef mcl::bn::Fr Fr;
typedef mcl::bn::G1 G1;
typedef mcl::bn::G2 G2;

//typedef mcl::bn::G1 G1;
//typedef mcl::bn::G2 G2;
//typedef mcl::bn::Fp12 Fp12;



//typedef Fr Zn;
//typedef mcl::EcT<Fp, Zn> Ec;


static const uint8_t* STRE;
static bool flag = false;
static size_t FSIZE = 1000;
static size_t MSIZE = 4;
static size_t BSIZE = 32;
static int BSELECT[20];// should be a vector;


void readBytes(uint8_t* buf, size_t size, std::ifstream& is) {
	cybozu::readSome(buf, size, is);
	buf[size] = '\0';
}



const mcl::EcParam& para = mcl::ecparam::secp256k1;


struct Sigma {
	Zn r;
	Zn s;
	//Ec t;
};

struct Sig {
    Zn r;
    Zn s;
    uint8_t* seed;
};

// 注意这里允许的字节数
struct Srm {
	uint8_t m[10000];
	uint8_t kf[640];
	int index[20];
};

struct SecretKey {
	Zn x1;
	mcl::bn::Fr x2;
};

struct PublicKey {
	mcl::fp::WindowMethod<Ec> wm_h;
	G1 P;
	G2 Q;
};

struct KeyPair {
	SecretKey sk;
	PublicKey pk;
};

struct State {
	bool flag;
	uint8_t estr[580];
};

struct PP {
    mcl::fp::WindowMethod<Ec> wm_g;
    //mcl::fp::WindowMethod<Ec> wm_h;
    mcl::bn::G1 P;
    mcl::bn::G2 Q;
};

struct Aux {
	uint8_t* key;  // committing key
	uint8_t* mac; // the result tag (i.e., tags)
	uint8_t* hm; // shared key (i.e., the salt u)
};


void Setup(PP& pp) {
	Ec G;
	mcl::initCurve<Ec>(para.curveType, &G);
    //const size_t bitSize = Zn::getBitSize();
    //Zn sec;
    //sec.setRand();
    //PP pp;
    pp.wm_g.init(G, 256, 10);
    //Ec::mul(H,G, sec);
    //pp.wm_g.mul(H, sec);
    //pp.wm_h.init(H,bitSize, 10);
    mcl::bn::initPairing(mcl::BLS12_381);
    mcl::bn::mapToG1(pp.P, 1);
    mcl::bn::mapToG2(pp.Q, 1);
    
}

/*
SecretKey KG(PP& pp, mcl::bn::G1& P, mcl::bn::G2& Q) {
	// should I use two keys?
	Zn x1;
	mcl::bn::Fr x2;
	
	
	x1.setRand();
	x2.setRand();
	Ec pub;
	pp.wm_g.mul(pub, x1);
	pp.wm_h.init(pub, 256, 10); // 作为公开参数，g是可以的，但pub公钥是个人拥有的，放在这里不太合适。
	mcl::bn::G1::mul(P, pp.P, x2);
	mcl::bn::G2::mul(Q, pp.Q, x2);
	return SecretKey {x1, x2};
}
*/

KeyPair KG(PP& pp) {
	SecretKey sk;
	PublicKey pk;
	sk.x1.setRand(); sk.x2.setRand();
	Ec pub;
	pp.wm_g.mul(pub, sk.x1);
	pk.wm_h.init(pub, 256,10);
	G1::mul(pk.P, pp.P, sk.x2);
	G2::mul(pk.Q, pp.Q, sk.x2);
	return KeyPair {sk, pk};
	  
}


void Sg(PP& pp, Sig& sig, const unsigned char* msg, Zn& sk) {
        std::string m = (const char*)msg;
        Zn &r = sig.r;
        Zn &s = sig.s;
        Zn z, k;
        Ec Q;
        z.setHashOf(m);
        for(; ;) {
			k.setRand();
            pp.wm_g.mul(Q, k);
            if (Q.isZero()) continue;
            Q.normalize();
            mcl::ecdsa::local::FpToZn(r, Q.x);
            if (r.isZero()) continue;
            Zn::mul(s,r, sk);
            s += z;
            if (s.isZero()) continue;
            s /= k;
            if (s.isNegative()) Zn::neg(s,s);
            return;
		}
    
}



bool Sv(PP& pp, PublicKey& pk, const Sig& sig, const unsigned char* msg) {
        std::string m = (const char*)msg;
        const Zn& r = sig.r;
		const Zn& s = sig.s;
		if (r.isZero() || s.isZero()) return false;
		if (s.isNegative()) return false;
		Zn z, w, u1, u2;
		z.setHashOf(m);
		Zn::inv(w, s);
		Zn::mul(u1, z, w);
		Zn::mul(u2, r, w);
		Ec Q1, Q2;
		//param.Pbase.mul(Q1, u1);
		pp.wm_g.mul(Q1, u1);
		//	Ec::mul(Q2, pub, u2);
		//mcl::ecdsa::local::mulDispatch(Q2, pub, u2);
		pk.wm_h.mul(Q2, u2);
		Q1 += Q2;
		if (Q1.isZero()) return false;
		Q1.normalize();
		Zn x;
		mcl::ecdsa::local::FpToZn(x, Q1.x);
		return r == x;
}

bool Sv(PP& pp, PublicKey& pk, const Sigma& sigma, const unsigned char* msg) {
        std::string m = (const char*)msg;
        const Zn& r = sigma.r;
		const Zn& s = sigma.s;
		if (r.isZero() || s.isZero()) return false;
		if (s.isNegative()) return false;
		Zn z, w, u1, u2;
		z.setHashOf(m);
		Zn::inv(w, s);
		Zn::mul(u1, z, w);
		Zn::mul(u2, r, w);
		Ec Q1, Q2;
		//param.Pbase.mul(Q1, u1);
		pp.wm_g.mul(Q1, u1);
		//	Ec::mul(Q2, pub, u2);
		//mcl::ecdsa::mulDispatch(Q2, pub, u2);
		pk.wm_h.mul(Q2, u2);
		Q1 += Q2;
		if (Q1.isZero()) return false;
		Q1.normalize();
		Zn x;
		mcl::ecdsa::local::FpToZn(x, Q1.x);
		return r == x;
       
}


long long ns_difference(struct timespec finish, struct timespec start) {
    long long NS_PER_SECOND = 1000000000;
    long long nsec_diff = finish.tv_nsec - start.tv_nsec;
    long long sec_diff = finish.tv_sec - start.tv_sec;
    return nsec_diff + sec_diff * NS_PER_SECOND;
    //return nsec_diff;
}


void Tg(uint8_t* key, uint8_t* seed, const uint8_t* msg, uint8_t* mac) {
	
	prg(seed, key, 32*MSIZE);
	for(int i = 0; i < MSIZE; i++) {
		hmac_it(key+i*32, msg+i*BSIZE, BSIZE, mac+i*32);
	}
}

bool Tv(const Srm& srm, const uint8_t* mac) {
	int j = 0;
	for(int i : srm.index) {
		if(i == -1) break;
		uint8_t* k = (uint8_t*)srm.kf+j*32;
		//const unsigned char* ms = srm.m+j*32;
		const unsigned char* ms = srm.m+j*BSIZE;
		
		const uint8_t* tag = mac+i*32;
		if(!verify_hmac(k, ms, BSIZE, tag)) {
			//printf("Bad %d\n", i);
			return false;
		}
		j++;
	}
	return true;
}


/*
void frank(uint8_t* key, SecretKey& sec, PP& pp, Sig& sig, const uint8_t* msg, 
     uint8_t* mac, uint8_t* hm, const mcl::bn::G1& P, const mcl::bn::G2& Q) {
	
	RAND_priv_bytes(sig.seed, 32);
	uint8_t* k = key;
	Tg(k, sig.seed, msg, mac);

	if(!flag) {
	    mcl::bn::Fp12 e1;
	    //mcl::bn::initPairing(mcl::BN254);
	    mcl::bn::pairing(e1, P,Q);
	    mcl::bn::Fp12::pow(e1, e1, sec.x2);
	    e1.serialize(hm, 600);
	    flag = true;
	}
	
	for(int i =0; i < 32*MSIZE; i++) {
		hm[i+576] = mac[i];
	}
	Sg(pp, sig, hm, sec.x1);
}
*/

void Frank(PP& pp, Aux& aux, Sig& sig, SecretKey& sec, PublicKey& pkr, 
           PublicKey& pkj, uint8_t* msg) {
	RAND_priv_bytes(sig.seed, 32);
	Tg(aux.key, sig.seed, msg, aux.mac);
	if(!flag) {
	    mcl::bn::Fp12 e1;
	    //mcl::bn::initPairing(mcl::BN254);
	    mcl::bn::pairing(e1, pkr.P,pkj.Q);
	    mcl::bn::Fp12::pow(e1, e1, sec.x2);
	    e1.serialize(aux.hm, 600);
	    flag = true;
	}
	
	for(int i =0; i < 32*MSIZE; i++) {
		aux.hm[i+576] = aux.mac[i];
	}
	Sg(pp, sig, aux.hm, sec.x1);
}

/*
bool verify(uint8_t* key, SecretKey& sec, PP& pp, const Sig& sig, const uint8_t* msg,
       uint8_t* mac, uint8_t* hm, const mcl::bn::G1& P, const mcl::bn::G2& Q) {
		
		uint8_t* k = key;
		Tg(k, sig.seed, msg, mac);
		if(!flag) {
			mcl::bn::Fp12 e1;
			mcl::bn::pairing(e1, P,Q);
			mcl::bn::Fp12::pow(e1, e1, sec.x2);
			e1.serialize(hm, 600);
			flag = true;
		}
		
		for(int i = 0; i < 32*MSIZE; i++) {
			hm[i+576] = mac[i];
	   }
		return Sv(pp, sig, hm);
}
*/

bool Verify(PP& pp, Aux& aux, Sig& sig, SecretKey& sec, PublicKey& pks, 
            PublicKey& pkj, uint8_t* msg) {
	    Tg(aux.key, sig.seed, msg, aux.mac);
		if(!flag) {
			mcl::bn::Fp12 e1;
			mcl::bn::pairing(e1, pks.P,pkj.Q);
			mcl::bn::Fp12::pow(e1, e1, sec.x2);
			e1.serialize(aux.hm, 600);
			flag = true;
		}
		
		for(int i = 0; i < 32*MSIZE; i++) {
			aux.hm[i+576] = aux.mac[i];
	   }
		return Sv(pp, pks, sig, aux.hm);		
}

/*
void report(uint8_t* key, const uint8_t* msg, uint8_t* mac, Srm& srm,  const Sig& sig, Sigma& sigma) {
	
	uint8_t* k = key;
	Tg(k, sig.seed, msg, mac);
	int h = 0;
	for(int i: BSELECT) {
		
		if(i == -1) break;
		//int j = 0;
		srm.index[h] = i;
		for(int j = 0; j < 32; j++) {
			//k = i*32;
			srm.kf[h*32+j] = key[i*32+j];
			//srm.m[h*BSIZE+j] = msg[i*BSIZE+j];
		}
		for(int j = 0; j < BSIZE; j++) {
			srm.m[h*BSIZE+j] = msg[i*BSIZE+j];
		}
		h++;
	}
	//srm.m[h*32] = '\0';
	srm.index[h] = -1;
	//free(sig.seed);
	//sig.seed = NULL;
	sigma.r = sig.r;
	sigma.s = sig.s;
	//free(sig.seed);  cannot free, other will be destructed.
}
*/

void Report(Aux& aux, Srm& srm, Sigma& sigma, const uint8_t* msg, 
            const int T[], const Sig& sig) {
	Tg(aux.key, sig.seed, msg, aux.mac);
	int h = 0;
	for(int i: BSELECT) {
		
		if(i == -1) break;
		//int j = 0;
		srm.index[h] = i;
		for(int j = 0; j < 32; j++) {
			//k = i*32;
			srm.kf[h*32+j] = aux.key[i*32+j];
			//srm.m[h*BSIZE+j] = msg[i*BSIZE+j];
		}
		for(int j = 0; j < BSIZE; j++) {
			srm.m[h*BSIZE+j] = msg[i*BSIZE+j];
		}
		h++;
	}
	//srm.m[h*32] = '\0';
	srm.index[h] = -1;
	//free(sig.seed);
	//sig.seed = NULL;
	sigma.r = sig.r;
	sigma.s = sig.s;
}
/*
bool judge(SecretKey& sec, PP& pp, const Srm& srm, const uint8_t* mac, uint8_t* hm, 
    const Sigma& sigma, const mcl::bn::G1& P, const mcl::bn::G2& Q) {
	
	if(!Tv(srm, mac)) {
		return false;
	}
	if(!flag) {
		mcl::bn::Fp12 e1;
		mcl::bn::pairing(e1, P,Q);
		mcl::bn::Fp12::pow(e1, e1, sec.x2);
		e1.serialize(hm, 600);
		flag = true;
	}
	
	for(int i = 0; i < 32*MSIZE; i++) {
		hm[i+576] = mac[i];
	}
	
	return Sv(pp, sigma, hm);
}

*/
bool Judge(PP& pp, Aux& aux, SecretKey& sec, PublicKey& pks, PublicKey& pkr, 
           const Srm& srm, const Sigma& sigma) {
	if(!Tv(srm, aux.mac)) {
		return false;
	}
	if(!flag) {
		mcl::bn::Fp12 e1;
		mcl::bn::pairing(e1, pks.P,pkr.Q);
		mcl::bn::Fp12::pow(e1, e1, sec.x2);
		e1.serialize(aux.hm, 600);
		flag = true;
	}
	
	for(int i = 0; i < 32*MSIZE; i++) {
		aux.hm[i+576] = aux.mac[i];
	}
	
	return Sv(pp, pks, sigma, aux.hm);		   
}

double sum(double *r, int n) {
	double s = 0;
	for(int i = 0; i < n; i++) {
		s = s + r[i];
	}
	s = s/(n*1000);
	return s;
}




