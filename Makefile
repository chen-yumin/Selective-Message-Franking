smf_main: symmetric.o smf_main.o
	g++ -o smf_main symmetric.o smf_main.o -I. -lm -lcrypto -lmcl
symmetric.o: symmetric.c
	gcc -c symmetric.c
smf_main.o: smf_main.cpp
	g++ -c smf_main.cpp

