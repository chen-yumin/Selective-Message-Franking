CC      = gcc
CXX     = g++
CFLAGS  = -std=c17 -O2 -march=native -DNDEBUG -I.
CXXFLAGS= -std=c++17 -O2 -march=native -DNDEBUG -I.
LDFLAGS = -lmcl -lcrypto -lm -lpthread

# C source
C_SRCS  = fe_encode.c symmetric.c
C_OBJS  = $(C_SRCS:.c=.o)

# C++ sources
ECDSA_CPP_SRC = test_smf_ecdsa_perf.cpp
BLS_CPP_SRC   = test_smf_bls_perf.cpp
ECDSA_OBJ     = $(ECDSA_CPP_SRC:.cpp=.o)
BLS_OBJ       = $(BLS_CPP_SRC:.cpp=.o)

# Target binaries
TARGET_ECDSA = test_smf_ecdsa_perf_opt
TARGET_BLS   = test_smf_bls_perf_opt
ALL_TARGETS  = $(TARGET_ECDSA) $(TARGET_BLS)

.PHONY: all clean
all: $(ALL_TARGETS)

# Link ecdsa binary
$(TARGET_ECDSA): $(C_OBJS) $(ECDSA_OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

# Link bls binary
$(TARGET_BLS): $(C_OBJS) $(BLS_OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

# Rule for C files
%.o: %.c
	$(CC) $(CFLAGS) -c $<

# Rule for C++ files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

clean:
	rm -f *.o $(ALL_TARGETS)

