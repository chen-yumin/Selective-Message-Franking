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




struct Sigma {
	mcl::bn::G1 sgn;
};

struct Sig {
    mcl::bn::G1 sgn;
    uint8_t* seed;
};


struct Srm {
	uint8_t* m;
	uint8_t* kf;
	int* index;
};

struct PP {
    mcl::bn::G2 G;
    mcl::bn::G1 G_1;
};

struct Aux {
	uint8_t* key;  // commitment key
	uint8_t* mac; // the result tag
	uint8_t* hm; // shared key (i.e., the salt u)
};

struct SecretKey {
	mcl::bn::Fr x;
};

struct PublicKey {
	mcl::bn::G1 h1;
	mcl::bn::G2 h2;
};


struct KeyPair {
	SecretKey sk;
	PublicKey pk;
};


struct State {
	bool flag;
	uint8_t estr[580];
};



static const uint8_t* STRE;
static bool flag = false;
static bool flag2 = false;
static size_t FSIZE = 1000;
static size_t MSIZE = 4;
static size_t RSIZE = 1;
static size_t BSIZE = 32;
static int *BSELECT;// should be a vector;


void readBytes(uint8_t* buf, size_t size, std::ifstream& is) {
	cybozu::readSome(buf, size, is);
	buf[size] = '\0';
}

void Setup(PP& pp) {
	
    mcl::bn::initPairing(mcl::BLS12_381);
    mcl::bn::mapToG2(pp.G,1);
    mcl::bn::mapToG1(pp.G_1, 1);
   
    
}

KeyPair KG(PP& pp) {
	SecretKey sk;
	PublicKey pk;
	sk.x.setRand();
	mcl::bn::G1::mul(pk.h1, pp.G_1, sk.x);
	mcl::bn::G2::mul(pk.h2, pp.G, sk.x);
	return KeyPair {sk, pk};
}



void Sg(PP& pp, Sig& sig, const unsigned char* msg, mcl::bn::Fr& sk) {
        std::string m = (const char*)msg;
        mcl::bn::Fp t;
        t.setHashOf(m);
        mcl::bn::G1 Hm;
        mcl::bn::mapToG1(Hm, t);
        mcl::bn::G1::mul(sig.sgn, Hm, sk);
    
}



bool Sv(PP& pp, PublicKey& pk, const Sig& sig, const unsigned char* msg) {
        std::string m = (const char*)msg;
        
		mcl::bn::Fp12 e1, e2;
	    mcl::bn::G1 Hm;
	    mcl::bn::Fp t;
	    t.setHashOf(m);
	    mcl::bn::mapToG1(Hm, t);
	    mcl::bn::pairing(e1, sig.sgn, pp.G);  // e1 = e(sig.sgn, G)
	    mcl::bn::pairing(e2, Hm, pk.h2);     // e2 = e(Hm, sG)
	    return e1 == e2;
}

bool Sv(PP& pp, PublicKey& pk, const Sigma& sigma, const unsigned char* msg) {
        std::string m = (const char*)msg;
		mcl::bn::Fp12 e1, e2;
	    mcl::bn::G1 Hm;
	    mcl::bn::Fp t;
	    t.setHashOf(m);
	    mcl::bn::mapToG1(Hm, t);
	    mcl::bn::pairing(e1, sigma.sgn, pp.G); // e1 = e(sigma.sgn, G)
	    mcl::bn::pairing(e2, Hm, pk.h2);      // e2 = e(Hm, sG)
	    return e1 == e2;
}


long long ns_difference(struct timespec finish, struct timespec start) {
    long long NS_PER_SECOND = 1000000000;
    long long nsec_diff = finish.tv_nsec - start.tv_nsec;
    long long sec_diff = finish.tv_sec - start.tv_sec;
    return nsec_diff + sec_diff * NS_PER_SECOND;
 
}


void Tg(uint8_t* key, uint8_t* seed, const uint8_t* msg, uint8_t* mac) {
	
	prg(seed, key, 32*MSIZE);
	for(int i = 0; i < MSIZE; i++) {
		hmac_it(key+i*32, msg+i*BSIZE, BSIZE, mac+i*32);
	}
}


bool Tv(const Srm& srm, const uint8_t* mac) {
	int j = 0;
	size_t t = 0;
	while(1) {
		
		int i = srm.index[t++];
		if(i == -1) break;
		
		uint8_t* k = (uint8_t*)srm.kf+j*32;
	
		const unsigned char* ms = srm.m+j*BSIZE;
		
		const uint8_t* tag = mac+i*32;
		if(!verify_hmac(k, ms, BSIZE, tag)) {
			
			return false;
		}
		j++;
	}
	
	return true;
}



void Frank(PP& pp, Aux& aux, Sig& sig, SecretKey& sec, PublicKey& pkr, 
           PublicKey& pkj, uint8_t* msg) {
	RAND_priv_bytes(sig.seed, 32);
	Tg(aux.key, sig.seed, msg, aux.mac);

	if(!flag) {
	    mcl::bn::Fp12 u;
	    //mcl::bn::initPairing(mcl::BN254);
	    mcl::bn::pairing(u, pkr.h1, pkj.h2);
	    mcl::bn::Fp12::pow(u, u, sec.x);
	    u.serialize(aux.hm, 576);
	    flag = true;
	}
	for(int i = 0; i < 32*MSIZE; i++) {
		aux.hm[i+576] = aux.mac[i];
	}
	Sg(pp, sig, aux.hm, sec.x);
}


bool Verify(PP& pp, Aux& aux, Sig& sig, SecretKey& sec, PublicKey& pks, 
            PublicKey& pkj, uint8_t* msg) {
		Tg(aux.key, sig.seed, msg, aux.mac);
		if(!flag) {
			mcl::bn::Fp12 u;
			mcl::bn::pairing(u, pks.h1,pkj.h2);
			mcl::bn::Fp12::pow(u, u, sec.x);
			u.serialize(aux.hm, 576);
			flag = true;
		}
		
		
		for(int i = 0; i < 32*MSIZE; i++) {
			aux.hm[i+576] = aux.mac[i];
		}
		
		return Sv(pp, pks, sig, aux.hm);
}



void Report(Aux& aux, Srm& srm, Sigma& sigma, const uint8_t* msg, 
            const int T[], const Sig& sig) {
	Tg(aux.key, sig.seed, msg, aux.mac);
	int h = 0;
	int t = 0;
	while(1) {
		int i = T[t++];
		if(i == -1) break;
		srm.index[h] = i;
		for(int j = 0; j < 32; j++) {
			srm.kf[h*32+j] = aux.key[i*32+j];
		}
		for(int j = 0; j < BSIZE; j++) {
			srm.m[h*BSIZE+j] = msg[i*BSIZE+j];
		}
		h++;
	}
	
	srm.index[h] = -1;
	sigma.sgn = sig.sgn;
}


bool Judge(PP& pp, Aux& aux, SecretKey& sec, PublicKey& pks, PublicKey& pkr, 
           const Srm& srm, const Sigma& sigma) {

	if(!Tv(srm, aux.mac)) {
		return false;
	}
	if(!flag2) {
		mcl::bn::Fp12 u;
		mcl::bn::pairing(u, pks.h1, pkr.h2);
		mcl::bn::Fp12::pow(u, u, sec.x);
		u.serialize(aux.hm, 576);
		
		flag2 = true;
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


