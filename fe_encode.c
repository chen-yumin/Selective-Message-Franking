#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

#include "fe_encode.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

//// 单块图像缓存：二进制数据 + 长度
//typedef struct {
    //uint8_t* data;
    //size_t len;
//} ImageBlock;

//// 存储所有分块结果
//typedef struct {
    //ImageBlock* blocks;
    //uint32_t count;
//} EncodeResult;

//// MCU 坐标矩形
//typedef struct {
    //int x0, y0;
    //int x1, y1;
//} McuRect;

//// 回调上下文，用于拼接jpg内存
//typedef struct {
    //uint8_t* buf;
    //size_t len;
//} WriteCtx;

// stb 写入回调（纯C函数，替代lambda）
static void stb_write_callback(void* ctx, void* data, int size)
{
    WriteCtx* wc = (WriteCtx*)ctx;
    size_t new_len = wc->len + size;
    uint8_t* new_buf = realloc(wc->buf, new_len);
    if (!new_buf) return;
    memcpy(new_buf + wc->len, data, size);
    wc->buf = new_buf;
    wc->len = new_len;
}

// 释放 EncodeResult 内存
void free_encode_result(EncodeResult* res)
{
    if (!res) return;
    for (uint32_t i = 0; i < res->count; i++) {
        free(res->blocks[i].data);
    }
    free(res->blocks);
    free(res);
}

// 将裁剪后的像素编码为 JPG 内存 buffer
static uint8_t* encode_rgba_to_jpg(const uint8_t* pixels, int w, int h, int ch, size_t* out_len, int quality)
{
    WriteCtx wc = {NULL, 0};
    int ret = stbi_write_jpg_to_func(stb_write_callback, &wc, w, h, ch, pixels, quality);
    if (ret == 0 || wc.buf == NULL) {
        free(wc.buf);
        return NULL;
    }
    *out_len = wc.len;
    return wc.buf;
}

//// 主分割函数：去掉默认参数，纯C标准
//EncodeResult* split_jpeg_file_encode(const char* img_path, int target_blocks, int quality)
//{
    //int w, h, ch;
    //// 读取原图 RGBA 像素
    //uint8_t* full_pixels = stbi_load(img_path, &w, &h, &ch, 4);
    //if (!full_pixels) {
        //fprintf(stderr, "stb_image load failed\n");
        //return NULL;
    //}

    //const int MCU_W = 16;
    //const int MCU_H = 16;
    //int mcu_cols = (w + MCU_W - 1) / MCU_W;
    //int mcu_rows = (h + MCU_H - 1) / MCU_H;
    //int total_mcu = mcu_cols * mcu_rows;

    //// 限制最大分块数不超过总MCU
    //if (target_blocks > total_mcu) target_blocks = total_mcu;
    //if (target_blocks <= 0) target_blocks = 1;

    //// 计算均分规则：前 n-1 块 base，最后一块剩余
    //int base_mcu = total_mcu / target_blocks;
    //int last_mcu = total_mcu - base_mcu * (target_blocks - 1);

    //// 预生成所有MCU坐标矩形
    //McuRect* all_mcu = malloc(total_mcu * sizeof(McuRect));
    //int idx = 0;
    //for (int r = 0; r < mcu_rows; r++) {
        //for (int c = 0; c < mcu_cols; c++) {
            //int x0 = c * MCU_W;
            //int y0 = r * MCU_H;
            //int x1 = x0 + MCU_W;
            //int y1 = y0 + MCU_H;
            //if (x1 > w) x1 = w;
            //if (y1 > h) y1 = h;
            //all_mcu[idx++] = (McuRect){x0, y0, x1, y1};
        //}
    //}

    //EncodeResult* res = malloc(sizeof(EncodeResult));
    //res->count = target_blocks;
    //res->blocks = malloc(target_blocks * sizeof(ImageBlock));

    //int ptr = 0;
    //for (int seg = 0; seg < target_blocks; seg++) {
        //int seg_mcu_cnt = (seg == target_blocks - 1) ? last_mcu : base_mcu;
        //// 取当前段所有MCU
        //int min_x = w, min_y = h, max_x = 0, max_y = 0;
        //for (int m = 0; m < seg_mcu_cnt; m++) {
            //McuRect mr = all_mcu[ptr + m];
            //if (mr.x0 < min_x) min_x = mr.x0;
            //if (mr.y0 < min_y) min_y = mr.y0;
            //if (mr.x1 > max_x) max_x = mr.x1;
            //if (mr.y1 > max_y) max_y = mr.y1;
        //}
        //// 裁剪区域宽高
        //int crop_w = max_x - min_x;
        //int crop_h = max_y - min_y;
        //// 提取裁剪像素
        //uint8_t* crop_pix = malloc(crop_w * crop_h * 4);
        //for (int y = 0; y < crop_h; y++) {
            //int src_y = min_y + y;
            //memcpy(
                //crop_pix + y * crop_w * 4,
                //full_pixels + (src_y * w + min_x) * 4,
                //crop_w * 4
            //);
        //}
        //// 编码为JPG内存块
        //size_t blk_len;
        //uint8_t* blk_data = encode_rgba_to_jpg(crop_pix, crop_w, crop_h, 4, &blk_len, quality);
        //res->blocks[seg].data = blk_data;
        //res->blocks[seg].len = blk_len;

        //free(crop_pix);
        //ptr += seg_mcu_cnt;
    //}

    //free(all_mcu);
    //stbi_image_free(full_pixels);
    //return res;
//}

// 主分割函数：去掉默认参数，纯C标准
EncodeResult* split_jpeg_file_encode(const char* img_path, int target_blocks, int quality)
{
    // ============ 优化分支：target_blocks == 1 直接返回原图 ============
    if (target_blocks == 1)
    {
        FILE* fp = fopen(img_path, "rb");
        if (!fp)
        {
            fprintf(stderr, "open image failed: %s\n", img_path);
            return NULL;
        }
        fseek(fp, 0, SEEK_END);
        long file_size = ftell(fp);
        rewind(fp);

        uint8_t* raw_buf = malloc(file_size);
        if (!raw_buf)
        {
            fclose(fp);
            fprintf(stderr, "malloc raw image buffer failed\n");
            return NULL;
        }
        fread(raw_buf, 1, file_size, fp);
        fclose(fp);

        EncodeResult* res = malloc(sizeof(EncodeResult));
        if (!res)
        {
            free(raw_buf);
            return NULL;
        }
        res->blocks = malloc(sizeof(ImageBlock));
        if (!res->blocks)
        {
            free(res);
            free(raw_buf);
            return NULL;
        }
        res->count = 1;
        res->blocks[0].data = raw_buf;
        res->blocks[0].len = (size_t)file_size;
        return res;
    }
    // ====================================================================

    // target_blocks > 1，沿用原有 stb 像素裁剪逻辑
    int w, h, ch;
    uint8_t* full_pixels = stbi_load(img_path, &w, &h, &ch, 4);
    if (!full_pixels)
    {
        fprintf(stderr, "stb_image load failed\n");
        return NULL;
    }

    const int MCU_W = 16;
    const int MCU_H = 16;
    int mcu_cols = (w + MCU_W - 1) / MCU_W;
    int mcu_rows = (h + MCU_H - 1) / MCU_H;
    int total_mcu = mcu_cols * mcu_rows;

    if (target_blocks > total_mcu) target_blocks = total_mcu;
    if (target_blocks <= 0) target_blocks = 1;

    int base_mcu = total_mcu / target_blocks;
    int last_mcu = total_mcu - base_mcu * (target_blocks - 1);

    McuRect* all_mcu = malloc(total_mcu * sizeof(McuRect));
    if (!all_mcu)
    {
        stbi_image_free(full_pixels);
        return NULL;
    }

    int idx = 0;
    for (int r = 0; r < mcu_rows; r++)
    {
        for (int c = 0; c < mcu_cols; c++)
        {
            int x0 = c * MCU_W;
            int y0 = r * MCU_H;
            int x1 = x0 + MCU_W;
            int y1 = y0 + MCU_H;
            if (x1 > w) x1 = w;
            if (y1 > h) y1 = h;
            all_mcu[idx++] = (McuRect){x0, y0, x1, y1};
        }
    }

    EncodeResult* res = malloc(sizeof(EncodeResult));
    if (!res)
    {
        free(all_mcu);
        stbi_image_free(full_pixels);
        return NULL;
    }
    res->count = target_blocks;
    res->blocks = malloc(target_blocks * sizeof(ImageBlock));
    if (!res->blocks)
    {
        free(res);
        free(all_mcu);
        stbi_image_free(full_pixels);
        return NULL;
    }

    int ptr = 0;
    for (int seg = 0; seg < target_blocks; seg++)
    {
        int seg_mcu_cnt = (seg == target_blocks - 1) ? last_mcu : base_mcu;
        int min_x = w, min_y = h, max_x = 0, max_y = 0;
        for (int m = 0; m < seg_mcu_cnt; m++)
        {
            McuRect mr = all_mcu[ptr + m];
            if (mr.x0 < min_x) min_x = mr.x0;
            if (mr.y0 < min_y) min_y = mr.y0;
            if (mr.x1 > max_x) max_x = mr.x1;
            if (mr.y1 > max_y) max_y = mr.y1;
        }
        int crop_w = max_x - min_x;
        int crop_h = max_y - min_y;

        uint8_t* crop_pix = malloc(crop_w * crop_h * 4);
        if (!crop_pix)
        {
            fprintf(stderr, "malloc crop pixel buffer failed\n");
            // 此处简化处理；上层调用者需要用 free_encode_result 释放已分配部分
            free(all_mcu);
            stbi_image_free(full_pixels);
            return NULL;
        }

        for (int y = 0; y < crop_h; y++)
        {
            int src_y = min_y + y;
            memcpy(
                crop_pix + y * crop_w * 4,
                full_pixels + (src_y * w + min_x) * 4,
                crop_w * 4
            );
        }

        size_t blk_len;
        uint8_t* blk_data = encode_rgba_to_jpg(crop_pix, crop_w, crop_h, 4, &blk_len, quality);
        res->blocks[seg].data = blk_data;
        res->blocks[seg].len = blk_len;

        free(crop_pix);
        ptr += seg_mcu_cnt;
    }

    free(all_mcu);
    stbi_image_free(full_pixels);
    return res;
}


// 将所有块打包为 .enode 单文件
int pack_to_enode(const char* enode_path, const EncodeResult* res)
{
    FILE* f = fopen(enode_path, "wb");
    if (!f) return -1;

    uint32_t total = res->count;
    fwrite(&total, sizeof(uint32_t), 1, f);

    // 写入每块长度
    for (uint32_t i = 0; i < total; i++) {
        uint32_t len = (uint32_t)res->blocks[i].len;
        fwrite(&len, sizeof(uint32_t), 1, f);
    }
    // 写入块二进制
    for (uint32_t i = 0; i < total; i++) {
        fwrite(res->blocks[i].data, 1, res->blocks[i].len, f);
    }
    fclose(f);
    return 0;
}

// 从 .enode 读取指定下标块，返回二进制，out_len输出长度
uint8_t* read_block_by_index(const char* enode_path, uint32_t idx, uint32_t* out_len)
{
    FILE* f = fopen(enode_path, "rb");
    if (!f) return NULL;

    uint32_t total;
    fread(&total, sizeof(uint32_t), 1, f);
    if (idx >= total) {
        fclose(f);
        return NULL;
    }

    uint32_t* lens = malloc(total * sizeof(uint32_t));
    fread(lens, sizeof(uint32_t), total, f);

    // 计算数据偏移
    uint32_t offset = 0;
    for (uint32_t i = 0; i < idx; i++) offset += lens[i];
    // 文件头部：4 + total*4
    long data_start = 4 + total * 4;
    fseek(f, data_start + offset, SEEK_SET);

    uint32_t blk_len = lens[idx];
    uint8_t* buf = malloc(blk_len);
    fread(buf, 1, blk_len, f);

    *out_len = blk_len;
    free(lens);
    fclose(f);
    return buf;
}

// 文本二进制均等分块，最后一块更小
EncodeResult* split_text_file_encode(const char* raw, size_t raw_len, int target_blocks)
{
    if (target_blocks <= 1) {
        EncodeResult* res = malloc(sizeof(EncodeResult));
        res->count = 1;
        res->blocks = malloc(sizeof(ImageBlock));
        res->blocks[0].len = raw_len;
        res->blocks[0].data = malloc(raw_len);
        memcpy(res->blocks[0].data, raw, raw_len);
        return res;
    }

    EncodeResult* res = malloc(sizeof(EncodeResult));
    res->count = target_blocks;
    res->blocks = malloc(target_blocks * sizeof(ImageBlock));

    size_t base = raw_len / target_blocks;
    size_t ptr = 0;
    for (int i = 0; i < target_blocks; i++) {
        size_t cur_len = (i == target_blocks - 1) ? (raw_len - ptr) : base;
        res->blocks[i].len = cur_len;
        res->blocks[i].data = malloc(cur_len);
        memcpy(res->blocks[i].data, raw + ptr, cur_len);
        ptr += cur_len;
    }
    return res;
}

// 读取完整enode文件到一块连续内存，返回总字节长度
size_t load_enode_to_memory(const char* enode_path, uint8_t** out_mem)
{
    FILE* f = fopen(enode_path, "rb");
    fseek(f, 0, SEEK_END);
    size_t total_size = ftell(f);
    rewind(f);
    uint8_t* buf = malloc(total_size);
    fread(buf, 1, total_size, f);
    fclose(f);
    *out_mem = buf;
    return total_size;
}


// 从srm->m中读取第blk_idx个数据块（m_{blk_idx+1}，跳过m0头部）
// data_out：输出块二进制指针（指向srm.m内部内存，无需free）
// return 块字节长度，出错返回0
uint32_t get_block_from_srm_m(const uint8_t* m_buf, int blk_idx, const uint8_t** data_out)
{
    // m_buf = srm->m，完整enode内存镜像
    uint32_t N = *(uint32_t*)m_buf;
    if (blk_idx < 0 || blk_idx >= N) return 0;

    // 长度数组起始位置：m_buf + 4
    const uint32_t* lens = (const uint32_t*)(m_buf + 4);
    // 数据区起始偏移 = 4 + N*4
    uint64_t data_start_off = 4 + 4ULL * N;
    // 累加前面所有块长度
    uint64_t blk_offset = 0;
    for(int i=0; i<blk_idx; i++){
        blk_offset += lens[i];
    }
    uint64_t abs_off = data_start_off + blk_offset;
    *data_out = m_buf + abs_off;
    return lens[blk_idx];
}

//int main()
//{
    //// 1. 分割图片为8个File Encode块，quality显式传85
    //EncodeResult* img_res = split_jpeg_file_encode("figures/pexels-manon-thvnd-40702295-30973663.jpg", 8, 85);
    //if (!img_res) {
        //fprintf(stderr, "split image failed\n");
        //return 1;
    //}

    //// 2. 打包成单文件 image.enode
    //pack_to_enode("image.enode", img_res);

    //// 3. 读取第3块
    //uint32_t blk_len;
    //uint8_t* blk = read_block_by_index("image.enode", 3, &blk_len);
    //if (blk) {
        //// 导出为jpg查看
        //FILE* out = fopen("view_block3.jpg", "wb");
        //fwrite(blk, 1, blk_len, out);
        //fclose(out);
        //free(blk);
    //}

    //free_encode_result(img_res);
    //return 0;
//}
