The code requires OpenSSL and mcl to be installed. To run the code for evaluation, run as follows:
```
make
```
To get the evaluation for a 1kB message (fixed on one block), run the following:
```
./smf_main 1000
```
To evaluate a 2kB message divided into 10 blocks, where 5 blocks are reported, run the following:
```
./smf_main 2000 10 5
```
The first arg (i.e., 2000) denotes the size of a message; the second arg (i.e., 10) denotes the number of blocks of that message; the third arg denotes the number of reporting blocks.
Note that, in this code, message size should be no more than 10000 bytes, and number of blocks should be no more than 20; otherwise, smf_main.cpp should be modified.
