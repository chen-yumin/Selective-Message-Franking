# Compiler and flags
CC = gcc
CXX = g++
CFLAGS = -I. -c
CXXFLAGS = -I. -c
LDFLAGS = -lm -lcrypto -lmcl

# Targets
TARGETS = smf_text_main smf_figure_main

# Default target
all: $(TARGETS)

# Text main program
smf_text_main: symmetric.o smf_text_main.o
	$(CXX) -o $@ $^ $(LDFLAGS)

# Figure main program
smf_figure_main: symmetric.o smf_figure_main.o
	$(CXX) -o $@ $^ $(LDFLAGS)

# Object files
symmetric.o: symmetric.c
	$(CC) $(CFLAGS) $< -o $@

smf_text_main.o: smf_text_main.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

smf_figure_main.o: smf_figure_main.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

# Cleanup
clean:
	rm -f *.o $(TARGETS)

.PHONY: all clean
