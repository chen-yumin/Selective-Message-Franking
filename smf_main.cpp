#include "smf_ecdsa.hpp"


int main(int argc, char* argv[]) {
    struct timespec finish, start;
    uint8_t* seed = (uint8_t *)malloc(32);
    uint8_t* output = (uint8_t *)malloc(640);
    
    uint8_t msg[10001];
    memset(BSELECT, -1, 24);
    std::ifstream infile;
    //infile.open("../sample/msg.txt");
    infile.open("msgs/msg11.txt");
    FSIZE = atoi(argv[1]);
    readBytes(msg, FSIZE, infile);
    infile.close();
    
    uint8_t mac[640];
    
    PP pp;
    Setup(pp);
    KeyPair KPs = KG(pp);
    KeyPair KPr = KG(pp);
    KeyPair KPj = KG(pp);
    
    mcl::bn::Fp12 e1;
    mcl::bn::pairing(e1, KPr.pk.P, KPj.pk.Q);
    mcl::bn::Fp12::pow(e1, e1, KPs.sk.x2);
    
    //std::cout << e1 << std::endl;
    // BLS12_381 576 Byte, BN254 384 Byte
    static unsigned char eStr[600];
    int l = e1.serialize(eStr, 600);
    
    //printf("%d\n", l);
    //MSIZE = 1; BSIZE = 32;
    //MSIZE = 1; BSIZE = FSIZE / MSIZE;
    if(argc == 2) {
		MSIZE = 1;
	} else {
		MSIZE = atoi(argv[2]);
	}
		//BSELECT[0] = 1; BSELECT[1] = 2;
	//BSELECT[0] = 0;
	if(MSIZE == 1) {
		BSELECT[0] = 0;
	}
	else {
		int t;
		//scanf("%d", &t);
		t = atoi(argv[3]);
		// Assume that the first t blocks are about to be reported. However, it can be designated.
		for(int i = 0; i < t; i++) {
			//scanf("%d", &BSELECT[i]);
			BSELECT[i] = i;
			
		}
	}
	BSIZE = FSIZE / MSIZE;
    //printf("%d\n", BSIZE);
    Sig sig;
    Sigma sigma;
    //sig.seed = (uint8_t*)malloc(32*sizeof(uint8_t));
    sig.seed = seed;
   
    //e1.serialize(eStr, 600);
    //static const unsigned char*STRE; 
    STRE = (const unsigned char*)eStr; 
    uint8_t hm[600+32*MSIZE];
    
	Srm srm;
	printf("frank,verify,pass?,report,judge,pass?\n");
	double results[4000];
	double result = 0;
	Aux aux;  aux.key = output; aux.mac = mac; aux.hm = hm;
	for(int i = 0; i < 1000; i++) {
		clock_gettime(CLOCK_REALTIME, &start);
		//frank(output, sec, pp, sig, msg, mac, hm, PR, QJ);
		Frank(pp, aux, sig, KPs.sk, KPr.pk, KPj.pk, msg);
		clock_gettime(CLOCK_REALTIME, &finish);
		results[i] = ns_difference(finish, start);
		printf("%lld,", ns_difference(finish, start));
		
		clock_gettime(CLOCK_REALTIME, &start);
		//bool b = verify(output, sec2, pp, sig, msg, mac, hm, PS, QJ);
		bool b = Verify(pp, aux, sig, KPr.sk, KPs.pk, KPj.pk, msg);
		clock_gettime(CLOCK_REALTIME, &finish);
		results[1000+i] = ns_difference(finish, start);
		printf("%lld,", ns_difference(finish, start));
		printf("%s,", b ? "OK" : "Bad");
		
		clock_gettime(CLOCK_REALTIME, &start);
		//report(output, msg, mac, srm, sig, sigma);
		Report(aux, srm,sigma, msg, BSELECT, sig);
		clock_gettime(CLOCK_REALTIME, &finish);
		results[2000+i] = ns_difference(finish, start);
		printf("%lld,", ns_difference(finish, start));
			
		clock_gettime(CLOCK_REALTIME, &start);
		//bool b2 = judge(sec3, pp, srm, mac, hm, sigma, PR, QJ);
		bool b2 = Judge(pp, aux, KPj.sk, KPs.pk, KPr.pk, srm, sigma);
		clock_gettime(CLOCK_REALTIME, &finish);
		results[3000+i] = ns_difference(finish, start);
		printf("%lld,", ns_difference(finish, start));
		printf("%s\n", b2 ? "Ok" : "Bad");
		
	}

	printf("%f %f %f %f\n", sum(results, 1000), sum(results+1000, 1000), sum(results+2000, 1000), sum(results+3000, 1000));
    
    return 0;
}


