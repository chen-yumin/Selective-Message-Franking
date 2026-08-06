#include "smf_bls.hpp"
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <algorithm>
#include <vector>
#include <cmath>
#include <cstring>
#include <fstream>
#include <random>

// ===================== 计时与统计工具（复用之前IQR过滤） =====================
//static long long ns_difference(const struct timespec& end, const struct timespec& start)
//{
    //long long sec = end.tv_sec - start.tv_sec;
    //long long nsec = end.tv_nsec - start.tv_nsec;
    //return sec * 1000000000LL + nsec;
//}

struct StatResult
{
    double raw_mean;
    double median;
    double filtered_mean;
    double std_dev;
    long long min_val;
    long long max_val;
    int total_cnt;
    int outlier_cnt;
};

static void calc_quartiles(const std::vector<long long>& sorted, double& Q1, double& Q3)
{
    int n = sorted.size();
    double idx_q1 = 0.25 * (n - 1);
    int i1 = (int)idx_q1;
    double frac1 = idx_q1 - i1;
    Q1 = sorted[i1] + frac1 * (sorted[i1 + 1] - sorted[i1]);

    double idx_q3 = 0.75 * (n - 1);
    int i3 = (int)idx_q3;
    double frac3 = idx_q3 - i3;
    Q3 = sorted[i3] + frac3 * (sorted[i3 + 1] - sorted[i3]);
}

static StatResult calc_stat(long long arr[], int len)
{
    StatResult res{};
    res.total_cnt = len;
    std::vector<long long> data(arr, arr + len);
    std::sort(data.begin(), data.end());
    res.min_val = data.front();
    res.max_val = data.back();

    int mid = len / 2;
    if (len % 2 == 1)
        res.median = data[mid];
    else
        res.median = (data[mid - 1] + data[mid]) / 2.0;

    double sum_raw = 0.0;
    for (auto v : data) sum_raw += v;
    res.raw_mean = sum_raw / len;

    double var = 0.0;
    for (auto v : data)
    {
        double diff = v - res.raw_mean;
        var += diff * diff;
    }
    res.std_dev = sqrt(var / len);

    double Q1, Q3;
    calc_quartiles(data, Q1, Q3);
    double IQR = Q3 - Q1;
    double lower = Q1 - 1.5 * IQR;
    double upper = Q3 + 1.5 * IQR;

    std::vector<long long> valid;
    for (auto v : data)
    {
        if (v >= lower && v <= upper)
            valid.push_back(v);
    }
    res.outlier_cnt = len - (int)valid.size();

    double sum_filter = 0.0;
    for (auto v : valid) sum_filter += v;
    res.filtered_mean = sum_filter / valid.size();
    return res;
}

// ===================== 工具函数 =====================
// 生成固定大小文本文件，填充'a'
static bool gen_fixed_size_txt(const char* path, size_t byte_size)
{
    FILE* fp = fopen(path, "wb");
    if (!fp) return false;
    const char buf[4096] = {0x61};
    size_t remain = byte_size;
    while (remain > 0)
    {
        size_t w = remain > 4096 ? 4096 : remain;
        fwrite(buf, 1, w, fp);
        remain -= w;
    }
    fclose(fp);
    return true;
}

// 随机抽取大于半数的块索引，返回T数组，末尾-1
// 随机抽取大于半数的块索引，返回T数组，末尾-1
static int* gen_major_index(int total_blk)
{
    int* T = new int[total_blk + 2];
    std::fill_n(T, total_blk + 2, -1);
    int take_num = total_blk / 2 + 1; // 严格过半
    std::vector<int> all(total_blk);
    for (int i = 0; i < total_blk; i++) all[i] = i;
    std::mt19937 rng(time(nullptr));
    std::shuffle(all.begin(), all.end(), rng);
    for (int i = 0; i < take_num; i++)
        T[i] = all[i];
    return T;
}


// 单次完整流程测试，返回四阶段统计
static void run_single_test(PP& pp, KeyPair& KPs, KeyPair& KPr, KeyPair& KPj,
         uint8_t* msg, int total_blk, int mlen, int* T_arr, StatResult out[4],
        int warmup_round = 100, int test_round = 500)
{
    size_t mac_len = total_blk * 32 + 32;
    uint8_t* seed = (uint8_t*)malloc(32);
    uint8_t* output = (uint8_t*)malloc(mac_len);
    uint8_t* mac_buf = new uint8_t[mac_len];
    uint8_t* kf_buf = new uint8_t[mac_len];
    uint8_t* full_mac = new uint8_t[mac_len]; // 原来栈数组改堆，防止栈溢出

    

    // 拷贝上报索引
    int* index_arr = new int[total_blk + 2];
    std::fill_n(index_arr, total_blk + 2, -1);
    int t_cnt = 0;
    while (T_arr[t_cnt] != -1)
    {
        index_arr[t_cnt] = T_arr[t_cnt];
        t_cnt++;
        
    }
    //size_t enode_buf_len = 4 + total_blk * 4;  // 头部大小
	//for (int i = 0; i < t_cnt; i++) {
	    //int idx = T_arr[i];
	    //uint32_t blk_len = *(uint32_t*)(msg + 4 + total_blk * 4 + idx * 4);
	    //enode_buf_len += blk_len;
	//}
	//uint8_t* srm_m = new uint8_t[mlen + 2048];
	// 统计选中分片真实总负载长度
	size_t payload_sum = 0;
	// 跳过头部4字节 + total_blk个uint32_t长度数组起始位置
	const uint8_t* lens_base = msg + 4 + total_blk * sizeof(uint32_t);
	for (int i = 0; i < t_cnt; ++i)
	{
		int idx = T_arr[i];
		uint32_t blk_len = *(const uint32_t*)(msg + 4 + idx * sizeof(uint32_t));
		payload_sum += blk_len;
	}

	// 根据真实总和分配缓冲区，额外预留1024字节冗余
	size_t buf_cap = payload_sum + 1024;
	uint8_t* srm_m = new uint8_t[buf_cap];
    memset(srm_m, 0, buf_cap);
    //printf("原始文件大小mlen: %zu\n", mlen);
	//printf("选中分片数量 t_cnt: %d\n", t_cnt);
	//printf("选中分片数据总和 payload_sum: %zu\n", payload_sum);
	//printf("差值: %zd\n", (ssize_t)payload_sum - (ssize_t)mlen);
	
    

    Srm srm;
    srm.m = srm_m;
    srm.kf = kf_buf;
    srm.index = index_arr;
    srm.full_mac = full_mac;

    long long frank[500], verify[500], report[500], judge[500];
    struct timespec st, ed;

    // 预热
    for (int w = 0; w < warmup_round; w++)
    {
        Aux aux;
        aux.key = output;
        aux.mac = mac_buf;
        Sig sig; Sigma sigma; sig.seed = seed;
        Frank(pp, aux, sig, KPs.sk, KPr.pk, KPj.pk, msg);
        Verify(pp, aux, sig, KPr.sk, KPs.pk, KPj.pk, msg);
        Report(aux, srm, sigma, msg, T_arr, sig, pp);
        Judge(pp, aux, KPj.sk, KPs.pk, KPr.pk, srm, sigma);
    }

    // 正式计时采集
    for (int i = 0; i < test_round; i++)
    {
        Aux aux;
        aux.key = output;
        aux.mac = mac_buf;
        Sig sig; Sigma sigma; sig.seed = seed;

        clock_gettime(CLOCK_MONOTONIC, &st);
        Frank(pp, aux, sig, KPs.sk, KPr.pk, KPj.pk, msg);
        clock_gettime(CLOCK_MONOTONIC, &ed);
        frank[i] = ns_difference(ed, st);

        clock_gettime(CLOCK_MONOTONIC, &st);
        Verify(pp, aux, sig, KPr.sk, KPs.pk, KPj.pk, msg);
        clock_gettime(CLOCK_MONOTONIC, &ed);
        verify[i] = ns_difference(ed, st);

        clock_gettime(CLOCK_MONOTONIC, &st);
        //Report(aux, srm, sigma, msg, BSELECT, sig, pp);
        Report(aux, srm, sigma, msg, T_arr, sig, pp);
        clock_gettime(CLOCK_MONOTONIC, &ed);
        report[i] = ns_difference(ed, st);

        clock_gettime(CLOCK_MONOTONIC, &st);
        Judge(pp, aux, KPj.sk, KPs.pk, KPr.pk, srm, sigma);
        clock_gettime(CLOCK_MONOTONIC, &ed);
        judge[i] = ns_difference(ed, st);
    }

    out[0] = calc_stat(frank, test_round);
    out[1] = calc_stat(verify, test_round);
    out[2] = calc_stat(report, test_round);
    out[3] = calc_stat(judge, test_round);

    // 全部释放，杜绝泄漏与double free
    free(seed);
    free(output);
    delete[] mac_buf;
    delete[] kf_buf;
    delete[] full_mac;
    delete[] srm_m;
    delete[] index_arr;
}


// ===================== 主测试入口 =====================
int main()
{
    // 密码系统全局初始化
    PP pp;
    Setup(pp);
    KeyPair KPs = KG(pp);
    KeyPair KPr = KG(pp);
    KeyPair KPj = KG(pp);

    // 测试参数配置
    const int warm = 100;
    const int loop = 500;
    // 实验1：梯度文件大小(字节)，全块上报
    std::vector<size_t> size_list = {
        256, 1024,
        4096, 8192, 12288, 16384, 65536, 131072, 262144, 512000
    };
    // 实验2：500KB固定，分块梯度
    std::vector<int> block_grad = {1, 2,4,8,16, 24, 32};

    // ========== 模块1：不同文件大小全块上报，输出 data_size_curve.csv（图1绘图数据） ==========
    std::ofstream f1("bls_data_size_curve.csv");
    f1 << "file_size_byte,block_num,frank_filter_us,verify_filter_us,report_filter_us,judge_filter_us,"
       << "frank_median,verify_median,report_median,judge_median\n";
    printf("===== 开始测试：不同文件尺寸全块上报 =====\n");

    for (size_t sz : size_list)
    {
        char tmp_txt[256];
        sprintf(tmp_txt, "tmp_%zu.txt", sz);
        gen_fixed_size_txt(tmp_txt, sz);
        
        FILE* fp = fopen(tmp_txt, "rb");
		if (!fp) { perror("fopen"); exit(1); }
		fseek(fp, 0, SEEK_END);
		size_t file_len = ftell(fp);
		rewind(fp);
		uint8_t* file_data = (uint8_t*)malloc(file_len);
		fread(file_data, 1, file_len, fp);
		fclose(fp);

        // 不分块：target_blocks=1 整块
        EncodeResult* res = split_text_file_encode((const char*)file_data, sz, 1);
        pack_to_enode("tmp.enode", res);
        free_encode_result(res);
        free(file_data);

        uint8_t* msg = nullptr;
        size_t mem_len = load_enode_to_memory("tmp.enode", &msg);
        uint32_t N = *(uint32_t*)msg;

        
        // 全块上报
		int* T = new int[N + 2];
		for (int i = 0; i < N; i++) T[i] = i;
		T[N] = -1;

		StatResult stat[4];
		run_single_test(pp, KPs, KPr, KPj, msg, N, sz, T, stat, warm, loop);

		delete[] T; // 使用完立刻释放


        // 写入CSV
        f1 << sz << "," << N << ","
           << stat[0].filtered_mean/1000.0 << "," << stat[1].filtered_mean/1000.0 << ","
           << stat[2].filtered_mean/1000.0 << "," << stat[3].filtered_mean/1000.0 << ","
           << stat[0].median/1000.0 << "," << stat[1].median/1000.0 << ","
           << stat[2].median/1000.0 << "," << stat[3].median/1000.0 << "\n";

        free(msg);
        remove(tmp_txt);
        remove("tmp.enode");
        printf("Finished size %zu bytes\n", sz);
    }
    f1.close();
    printf("模块1完成，数据保存至 bls_data_size_curve.csv\n\n");

    // ========== 模块2：固定500KB，多梯度分块、过半上报，输出 block_grad_curve.csv ==========
    std::ofstream f2("bls_block_grad_curve.csv");
    f2 << "total_block,report_block_cnt,frank_filter_us,verify_filter_us,report_filter_us,judge_filter_us,"
       << "frank_median,verify_median,report_median,judge_median\n";
    printf("===== 开始测试：500KB多梯度分块（上报>半数） =====\n");

    const size_t fixed_sz = 512000;
    char fixed_txt[256];
    sprintf(fixed_txt, "fixed_500k.txt");
    //const char* img_path = "fixed_500k.jpg";
    gen_fixed_size_txt(fixed_txt, fixed_sz);

    for (int blk : block_grad)
    {
		
		//FILE* fp = fopen(fixed_txt, "rb");
		//if (!fp) { perror("fopen"); exit(1); }
		//fseek(fp, 0, SEEK_END);
		//size_t file_len = ftell(fp);
		//rewind(fp);
		//uint8_t* file_data = (uint8_t*)malloc(file_len);
		//fread(file_data, 1, file_len, fp);
		//fclose(fp);
        //EncodeResult* res = split_text_file_encode((const char*)file_data, fixed_sz, blk);
        
        const char* img_path = "pexels-724211268-34418112.jpg";
		EncodeResult* res = split_jpeg_file_encode(img_path, blk, 85);
        pack_to_enode("fixed.enode", res);
        free_encode_result(res);
        //free(file_data);

        uint8_t* msg = nullptr;
        size_t mem_len = load_enode_to_memory("fixed.enode", &msg);
        uint32_t N = *(uint32_t*)msg;

        int* T = gen_major_index(blk);
		int take = 0;
		while (T[take] != -1) take++;
		
		StatResult stat[4];
		run_single_test(pp, KPs, KPr, KPj, msg, blk, 512000, T, stat, warm, loop);
		
		delete[] T; // 释放生成的索引数组


        f2 << blk << "," << take << ","
           << stat[0].filtered_mean/1000.0 << "," << stat[1].filtered_mean/1000.0 << ","
           << stat[2].filtered_mean/1000.0 << "," << stat[3].filtered_mean/1000.0 << ","
           << stat[0].median/1000.0 << "," << stat[1].median/1000.0 << ","
           << stat[2].median/1000.0 << "," << stat[3].median/1000.0 << "\n";

        free(msg);
        remove("fixed.enode");
        printf("Finished block count %d\n", blk);
    }
    f2.close();
    //remove(fixed_txt);
    printf("模块2完成，数据保存至 bls_block_grad_curve.csv\n\n");

    printf("全部测试完成！\n");
    printf("1. 尺寸-延迟曲线绘图数据：bls_data_size_curve.csv\n");
    printf("2. 分块数量-延迟曲线绘图数据：bls_block_grad_curve.csv\n");
    return 0;
}
