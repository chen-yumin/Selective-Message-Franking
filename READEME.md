This repository contains the implementation code for the paper:
"Privacy-Preserving Selective Message Franking: Minimizing Exposure to Encourage Abuse Reporting"

#############
Prerequisites

 OpenSSL
 mcl (Miracl Crypto Library)
 
############
Installation & Build
```
make
```
This will generate two executable files:
smf_text_main-For text message processing
smf_figure_main-For image/figure processing

############
Usage

+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Text Message Evaluation (smf_text_main)
Single Block Message

To evaluate a 1KB message (processed as a single block):
```
./smf_text_main 1000
```
Process Flow:
1. Sender signs the entire message block
2. Receiver verifies and reports the block
3. Moderator authenticates the reported block

Multi-Block Message
To evaluate a 2KB message divided into 10 blocks with 5 blocks reported:
```
./smf_text_main 2000 10 5
```
Parameters:
1. Message size in bytes (2000)
2. Total number of blocks (10)
3. Number of blocks to report (5, defaults to first 5 blocks if unspecified)

Process Flow:
1. Message is split into 10 blocks
2. Receiver selects and reports 5 blocks
3. Moderator authenticates the reported blocks
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Image Evaluation (smf_figure_main)
To evaluate an image divided into an r×c grid with t blocks reported:
```
./smf_figure_main r c t
```
Parameters:
1. Number of rows (r)
2. Number of columns (c)
3. Number of blocks to report (t, defaults to first t blocks if unspecified)

Features:
Uses stb_image.h and stb_image_write.h for image processing
Receiver submits only t blocks to the moderator
Moderator reconstructs a privacy-preserved version of the image
