#include "smf_ecdsa.hpp"
#include <algorithm>
const int MAX_FILESIZE = 1000001;
int parse(int argc, char *argv[]) {
	size_t t = 1;
	if(argc == 2) {
		MSIZE = 1;
	}    // ./smf_main 1000   not splited.
	else {
		MSIZE = atoi(argv[2]);
		t = atoi(argv[3]);
		
	} // ./smf_main 1000 l t   split the message into l blocks and reort with t blocks.
	return t;
}

uint8_t msg[MAX_FILESIZE];

int main(int argc, char* argv[]) {
	RSIZE = parse(argc, argv);
	BSELECT = new int[MSIZE+1];
	std::fill_n(BSELECT, MSIZE+1, -1);
    struct timespec finish, start;
    uint8_t* seed = (uint8_t *)malloc(32);
    uint8_t* output = (uint8_t *)malloc(MSIZE*32);
   
    uint8_t mac[MSIZE*32];
    int index[RSIZE+1];
    
    Ec u;
    std::ifstream infile;
    infile.open("msgs/msg500.txt");
    int input_size = atoi(argv[1]);
    FSIZE = input_size - (input_size % MSIZE);  // 
    readBytes(msg, FSIZE, infile);
    infile.close();
    
    BSIZE = FSIZE / MSIZE;
    uint8_t message[BSIZE*RSIZE];
    
    PP pp;
    Setup(pp);
    KeyPair KPs = KG(pp);
    KeyPair KPr = KG(pp);
    KeyPairj KPj = KGj(pp);
    
    Sig sig;
    Sigma sigma;
    sig.seed = seed;
    uint8_t hm[256+32*MSIZE];
    uint8_t kf[MSIZE*32];
	Srm srm;
	srm.m = message; srm.kf = kf; srm.index = index; 
	
	// Default set
	for(int i = 0; i < RSIZE; i++) {
		BSELECT[i] = i;
	}
	printf("frank,verify,pass?,report,judge,pass?\n");
	int offeset = 1000;
	double results[offeset*4];
	double result = 0;
	Aux aux;  aux.key = output; aux.mac = mac; aux.hm = hm;
	for(int i = 0; i < offeset; i++) {
		clock_gettime(CLOCK_REALTIME, &start);
		
		Frank(pp, aux, sig, KPs.sk, KPr.pk, KPj.pk, msg);
		clock_gettime(CLOCK_REALTIME, &finish);
		results[i] = ns_difference(finish, start);
		printf("%lld,", ns_difference(finish, start));
		
		clock_gettime(CLOCK_REALTIME, &start);
		bool b = Verify(pp, aux, sig, KPr.sk, KPs.pk, KPj.pk, msg);
		clock_gettime(CLOCK_REALTIME, &finish);
		results[offeset+i] = ns_difference(finish, start);
		printf("%lld,", ns_difference(finish, start));
		printf("%s,", b ? "OK" : "Bad");
		
		clock_gettime(CLOCK_REALTIME, &start);
		//Report(aux, srm,sigma, msg, BSELECT, sig);
		Report(aux, srm, sigma, msg, BSELECT, sig, pp, KPs.pk, KPj.pk, KPr.sk);
		clock_gettime(CLOCK_REALTIME, &finish);
		results[2*offeset+i] = ns_difference(finish, start);
		printf("%lld,", ns_difference(finish, start));
		
		clock_gettime(CLOCK_REALTIME, &start);
		bool b2 = Judge(pp, aux, KPj.sk, KPs.pk, KPr.pk, srm, sigma);
		clock_gettime(CLOCK_REALTIME, &finish);
		results[3*offeset+i] = ns_difference(finish, start);
		printf("%lld,", ns_difference(finish, start));
		printf("%s\n", b2 ? "Ok" : "Bad");
		
	}
	delete[] BSELECT;

	printf("%f %f %f %f\n", sum(results, offeset), sum(results+offeset, offeset), sum(results+2*offeset, offeset), 
	         sum(results+3*offeset, offeset));
    
    return 0;
}


