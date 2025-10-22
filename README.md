# Selective Message Franking

Implementation code for the paper: "Selective Message Franking: Encouraging Abuse Reports for Metadata-Private Content Moderation"

## Prerequisites

- OpenSSL
- mcl (herumi mcl)

## Installation & Build
make

This will generate four executable files:

- SMF-A:
  - `smf_ecdsa_text_main` for text message processing
  - `smf_ecdsa_figure_main` for image/figure processing

- SMF-B:
  - `smf_bls_text_main` for text message processing
  - `smf_bls_figure_main` for image/figure processing

## Usage

### Text Message Evaluation (smf_*_text_main)
**Full reporting**

To evaluate a 1KB message (processed as a single block) using SMF-A or SMF-B:
./smf_ecdsa_text_main 1024
or
./smf_bls_text_main 1024

Process Flow:
1. Sender signs the entire message block
2. Receiver verifies and reports the block
3. Moderator authenticates the reported block

### Image Evaluation (smf_*_figure_main)
**Selective reporting**

To evaluate an 500KB (decompressed) image divided into r×c grid (l blocks, l = r x c) with t blocks reported using SMF-A or SMF-B:
./smf_ecdsa_figure_main r c t
or
./smf_bls_figure_main r c t

Parameters:
- Number of rows (r)
- Number of columns (c)
- Number of blocks to report (t, defaults to first t blocks if unspecified)

Features:
- Uses stb_image.h and stb_image_write.h for image processing
- Receiver submits only t blocks to the moderator
- Moderator reconstructs a privacy-preserved version of the image


