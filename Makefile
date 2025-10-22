# Compiler and flags
CC = gcc
CXX = g++
CFLAGS = -I. -c -O2
CXXFLAGS = -I. -c -O2 -std=c++11
LDFLAGS = -lm -lcrypto -lmcl

# Targets
TARGETS = smf_ecdsa_text_main smf_ecdsa_figure_main smf_bls_text_main smf_bls_figure_main

# Default target
all: $(TARGETS)

# ECDSA text main program
smf_ecdsa_text_main: symmetric.o smf_ecdsa_text_main.o
	$(CXX) -o $@ $^ $(LDFLAGS)

# ECDSA figure main program  
smf_ecdsa_figure_main: symmetric.o smf_ecdsa_figure_main.o
	$(CXX) -o $@ $^ $(LDFLAGS)

# BLS text main program
smf_bls_text_main: symmetric.o smf_bls_text_main.o
	$(CXX) -o $@ $^ $(LDFLAGS)

# BLS figure main program
smf_bls_figure_main: symmetric.o smf_bls_figure_main.o
	$(CXX) -o $@ $^ $(LDFLAGS)

# Object files
symmetric.o: symmetric.c
	$(CC) $(CFLAGS) $< -o $@

smf_ecdsa_text_main.o: smf_ecdsa_text_main.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

smf_ecdsa_figure_main.o: smf_ecdsa_figure_main.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

smf_bls_text_main.o: smf_bls_text_main.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

smf_bls_figure_main.o: smf_bls_figure_main.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

# Cleanup
clean:
	rm -f *.o $(TARGETS)

.PHONY: all clean
