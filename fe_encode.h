#ifndef FE_ENCODE_H
#define FE_ENCODE_H

#include <stdint.h>
#include <stdio.h>

typedef struct {
    uint8_t* data;
    size_t len;
} ImageBlock;

typedef struct {
    ImageBlock* blocks;
    uint32_t count;
} EncodeResult;

typedef struct {
    int x0, y0;
    int x1, y1;
} McuRect;

typedef struct {
    uint8_t* buf;
    size_t len;
} WriteCtx;

//// 函数声明
//void free_encode_result(EncodeResult* res);
//static uint8_t* encode_rgba_to_jpg(const uint8_t* pixels, int w, int h, int ch, size_t* out_len, int quality);
//EncodeResult* split_jpeg_file_encode(const char* img_path, int target_blocks, int quality);
//int pack_to_enode(const char* enode_path, const EncodeResult* res);
//uint8_t* read_block_by_index(const char* enode_path, uint32_t idx, uint32_t* out_len);
//EncodeResult* split_text_file_encode(const uint8_t* raw, size_t raw_len, int target_blocks);
//void print_enode_meta(const char* enode_path);
//size_t load_enode_to_memory(const char* enode_path, uint8_t** out_mem);
//uint32_t get_block_from_srm_m(const uint8_t* m_buf, int blk_idx, const uint8_t** data_out);

#ifdef __cplusplus
extern "C" {
#endif

// 所有C接口放这里（上面声明如果是对外调用，包进extern "C"）
void free_encode_result(EncodeResult* res);
static uint8_t* encode_rgba_to_jpg(const uint8_t* pixels, int w, int h, int ch, size_t* out_len, int quality);
EncodeResult* split_jpeg_file_encode(const char* img_path, int target_blocks, int quality);
int pack_to_enode(const char* enode_path, const EncodeResult* res);
uint8_t* read_block_by_index(const char* enode_path, uint32_t idx, uint32_t* out_len);
EncodeResult* split_text_file_encode(const char* raw, size_t raw_len, int target_blocks);
void print_enode_meta(const char* enode_path);
size_t load_enode_to_memory(const char* enode_path, uint8_t** out_mem);
uint32_t get_block_from_srm_m(const uint8_t* m_buf, int blk_idx, const uint8_t** data_out);

#ifdef __cplusplus
}
#endif

#endif
