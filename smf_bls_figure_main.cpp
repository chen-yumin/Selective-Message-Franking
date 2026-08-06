#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "smf_bls.hpp"
#include "stb_image.h"
#include "stb_image_write.h"
#include <vector>
#include <string>
#include <stdexcept>
#include <memory>
#include <algorithm>
#include <cfloat>
#include <string>
#include <algorithm>
#include <fstream>
#include <iostream>

int parse(int argc, char *argv[]) {
    int t = 1;
    if (argc == 1) {
        MSIZE = 1;
    }
    else if (argc == 3) {
        MSIZE = atoi(argv[1])*atoi(argv[2]);
    }
    else {
        MSIZE = atoi(argv[1])*atoi(argv[2]);
        t = atoi(argv[3]);
    }
    return t;
}

enum class FillMode {
    BLACK,      // Fill missing blocks with black
    WHITE,      // Fill missing blocks with white
    AVERAGE,    // Fill with the average color of existing blocks
    NEAREST,    // Fill with the color of the nearest block
    CHECKERBOARD // Checkerboard fill pattern
};

/**
 * @brief Split image into grid blocks in pixel data
 * @param inputPath Input image path
 * @param[out] width Output image width
 * @param[out] height Output image height
 * @param[out] channels Output number of channels
 * @param rows Number of rows in grid
 * @param cols Number of columns in grid
 * @return std::vector<unsigned char> Contiguously stored pixel data of all blocks
 */
std::vector<unsigned char> gridSplitImagePixels(
    const char* inputPath,
    int& width, int& height, int& channels,
    int rows, int cols)
{
    // Load source image
    unsigned char* data = stbi_load(inputPath, &width, &height, &channels, 0);
    if (!data) {
        throw std::runtime_error("Failed to load image: " + std::string(stbi_failure_reason()));
    }

    // Adjust size to be exactly divisible by grid dimensions
    const int newWidth = (width / cols) * cols;
    const int newHeight = (height / rows) * rows;
    
    if (newWidth <= 0 || newHeight <= 0) {
        stbi_image_free(data);
        throw std::runtime_error("Image too small for the grid");
    }

    // Crop image to divisible dimensions
    std::vector<unsigned char> cropped(newWidth * newHeight * channels);
    for (int y = 0; y < newHeight; ++y) {
        const unsigned char* src = data + y * width * channels;
        unsigned char* dst = cropped.data() + y * newWidth * channels;
        std::copy_n(src, newWidth * channels, dst);
    }

    stbi_image_free(data);
    width = newWidth;
    height = newHeight;

    // Calculate tile dimensions
    const int tileW = width / cols;
    const int tileH = height / rows;
    const size_t tileSize = tileW * tileH * channels;

    // Allocate memory for all tiles in contiguous storage
    std::vector<unsigned char> buffer(rows * cols * tileSize);

    // Partition image into grid tiles
    for (int y = 0; y < rows; ++y) {
        for (int x = 0; x < cols; ++x) {
            const size_t tileOffset = (y * cols + x) * tileSize;
            
            // Copy pixel data for this tile
            for (int row = 0; row < tileH; ++row) {
                const unsigned char* src = cropped.data() + 
                    (y * tileH + row) * width * channels + x * tileW * channels;
                unsigned char* dst = buffer.data() + tileOffset + row * tileW * channels;
                std::copy_n(src, tileW * channels, dst);
            }
        }
    }

    return buffer;
}

/**
 * @brief Calculate average color from pixel data
 * @param pixelData Input pixel data
 * @param width Image width
 * @param height Image height
 * @param channels Number of color channels
 * @param[out] avgColor Calculated average color
 */
void calculateAverageColor(const std::vector<unsigned char>& pixelData,
                          int width, int height, int channels,
                          unsigned char avgColor[4]) 
{
    size_t totalPixels = width * height;
    memset(avgColor, 0, 4);
    
    if (totalPixels == 0) return;
    
    // Sum all pixel values
    for (size_t i = 0; i < pixelData.size(); i += channels) {
        for (int c = 0; c < channels; ++c) {
            avgColor[c] += pixelData[i + c];
        }
    }
    
    // Calculate average for each channel
    for (int c = 0; c < channels; ++c) {
        avgColor[c] /= totalPixels;
    }
    if (channels == 4) avgColor[3] = 255;
}

/**
 * @brief Reconstruct image from tiled pixel data with missing block handling
 * @param pixelData Contiguous pixel data of all tiles
 * @param width Original image width
 * @param height Original image height
 * @param channels Number of color channels
 * @param gridRows Number of tile rows
 * @param gridCols Number of tile columns
 * @param available Boolean array marking available tiles
 * @param mode Fill mode for missing tiles
 * @return Reconstructed image pixel data
 */
std::vector<unsigned char> restoreImageFromPixels(
    const std::vector<unsigned char>& pixelData,
    int width, int height, int channels,
    int gridRows, int gridCols,
    const std::vector<bool>& available,
    FillMode mode = FillMode::WHITE) 
{
    // Validate parameters
    if (available.size() != static_cast<size_t>(gridRows * gridCols)) {
        throw std::invalid_argument("Available tiles size mismatch");
    }

    const int imgWidth = width;
    const int imgHeight = height;
    std::vector<unsigned char> result(imgWidth * imgHeight * channels, 0);

    // Calculate tile dimensions
    const int tileWidth = imgWidth / gridCols;
    const int tileHeight = imgHeight / gridRows;
    const size_t tileSize = tileWidth * tileHeight * channels;

    // Preprocessing: Calculate average color for fill modes
    unsigned char avgR = 128, avgG = 128, avgB = 128, avgA = 255;
    if (mode == FillMode::AVERAGE || mode == FillMode::NEAREST) {
        unsigned char avgColor[4] = {0};
        calculateAverageColor(pixelData, imgWidth, imgHeight, channels, avgColor);
        avgR = avgColor[0];
        avgG = channels > 1 ? avgColor[1] : avgR;
        avgB = channels > 2 ? avgColor[2] : avgG;
        avgA = channels > 3 ? avgColor[3] : 255;
    }

    // Process each tile in the grid
    for (int y = 0; y < gridRows; ++y) {
        for (int x = 0; x < gridCols; ++x) {
            size_t tileIndex = y * gridCols + x;
            
            // Copy data from available tiles
            if (available[tileIndex]) {
                size_t tileOffset = tileIndex * tileSize;
                for (int row = 0; row < tileHeight; ++row) {
                    int globalY = y * tileHeight + row;
                    if (globalY >= imgHeight) continue;
                    
                    for (int col = 0; col < tileWidth; ++col) {
                        int globalX = x * tileWidth + col;
                        if (globalX >= imgWidth) continue;
                        
                        size_t srcPos = tileOffset + (row * tileWidth + col) * channels;
                        size_t dstPos = (globalY * imgWidth + globalX) * channels;
                        for (int c = 0; c < channels; ++c) {
                            result[dstPos + c] = pixelData[srcPos + c];
                        }
                    }
                }
                continue;
            }
            
            // Handle missing tiles with specified fill mode
            for (int row = 0; row < tileHeight; ++row) {
                int globalY = y * tileHeight + row;
                if (globalY >= imgHeight) continue;
                
                for (int col = 0; col < tileWidth; ++col) {
                    int globalX = x * tileWidth + col;
                    if (globalX >= imgWidth) continue;
                    
                    size_t pos = (globalY * imgWidth + globalX) * channels;
                    
                    switch (mode) {
                        case FillMode::BLACK:
                            for (int c = 0; c < channels; ++c) {
                                result[pos + c] = 0;
                            }
                            if (channels == 4) result[pos + 3] = 255;
                            break;
                            
                        case FillMode::WHITE:
                            for (int c = 0; c < channels; ++c) {
                                result[pos + c] = 255;
                            }
                            if (channels == 4) result[pos + 3] = 255;
                            break;
                            
                        case FillMode::AVERAGE:
                            result[pos] = avgR;
                            if (channels > 1) result[pos + 1] = avgG;
                            if (channels > 2) result[pos + 2] = avgB;
                            if (channels > 3) result[pos + 3] = avgA;
                            break;
                            
                        case FillMode::NEAREST: {
                            // Find nearest available tile
                            float minDist = FLT_MAX;
                            int nearestX = -1, nearestY = -1;
                            
                            for (int ny = 0; ny < gridRows; ++ny) {
                                for (int nx = 0; nx < gridCols; ++nx) {
                                    if (available[ny * gridCols + nx]) {
                                        float dist = std::hypot(x - nx, y - ny);
                                        if (dist < minDist) {
                                            minDist = dist;
                                            nearestX = nx;
                                            nearestY = ny;
                                        }
                                    }
                                }
                            }
                            
                            if (nearestX >= 0) {
                                size_t nearestOffset = (nearestY * gridCols + nearestX) * tileSize;
                                // Use center pixel color from nearest tile
                                size_t centerPos = nearestOffset + 
                                                 (tileHeight/2 * tileWidth + tileWidth/2) * channels;
                                for (int c = 0; c < channels; ++c) {
                                    result[pos + c] = pixelData[centerPos + c];
                                }
                            } else {
                                // Fallback to average color
                                result[pos] = avgR;
                                if (channels > 1) result[pos + 1] = avgG;
                                if (channels > 2) result[pos + 2] = avgB;
                                if (channels > 3) result[pos + 3] = avgA;
                            }
                            break;
                        }
                            
                        case FillMode::CHECKERBOARD: {
                            // Create checkerboard pattern based on position
                            bool isBlack = ((globalX/32 + globalY/32) % 2) == 0;
                            unsigned char val = isBlack ? 0 : 255;
                            for (int c = 0; c < channels; ++c) {
                                result[pos + c] = c == 3 ? 255 : val;
                            }
                            break;
                        }
                    }
                }
            }
        }
    }
    
    return result;
}

int main(int argc, char* argv[]) {
    struct timespec finish, start;
    int t = parse(argc, argv);
    BSELECT = new int[MSIZE+1];
    std::fill_n(BSELECT, MSIZE+1, -1);
    
    int rows = atoi(argv[1]), cols = atoi(argv[2]);
    int numbers = rows * cols;
    int width, height, channels;
    
    // Split image into pixel blocks for performance testing
    auto mm = gridSplitImagePixels("figures/pexels-nurgul-kelebek-83496198-16983338.jpg", 
                                  width, height, channels, rows, cols);
    
    printf("Image dimensions: %d x %d, Channels: %d\n", width, height, channels);
    printf("Total bytes after splitting: %ld\n", mm.size());
    
    // Performance testing setup
    uint8_t* seed = (uint8_t *)malloc(32);
    uint8_t* output = (uint8_t *)malloc(MSIZE*32);
    uint8_t mac[MSIZE*32];
    int index[t+1];
    
    unsigned char* msg = mm.data();
    if (!msg) return -1;
    FSIZE = mm.size();
    BSIZE = FSIZE / MSIZE;
    
    PP pp;
    Setup(pp);
    KeyPair KPs = KG(pp);
    KeyPair KPr = KG(pp);
    KeyPair KPj = KG(pp);
    
    Sig sig;
    Sigma sigma;
    sig.seed = seed;
   
    uint8_t hm[576+32*MSIZE];
    uint8_t kf[MSIZE*32];
    uint8_t* message = new uint8_t[BSIZE*t+1];
    if(!message) {
        printf("Memory allocation failed");
        return -1;
    }
    
    Srm srm;
    srm.m = message; srm.kf = kf; srm.index = index;
    
    // Select first t blocks for testing
    for(int i = 0; i < t; i++) {
        BSELECT[i] = i;
    }
    printf("frank,verify,pass?,report,judge,pass?\n");

    int offeset = 1000;
    double results[4*offeset];
    Aux aux;  aux.key = output; aux.mac = mac; aux.hm = hm;
    
    // Performance testing loop
    for(int i = 0; i < offeset; i++) {
        clock_gettime(CLOCK_REALTIME, &start);
        
        Frank(pp, aux, sig, KPs.sk, KPr.pk, KPj.pk, msg);
        clock_gettime(CLOCK_REALTIME, &finish);
        results[i] = ns_difference(finish, start);
        printf("%lld,", ns_difference(finish, start));
        
        clock_gettime(CLOCK_REALTIME, &start);
        bool b = Verify(pp, aux, sig, KPr.sk, KPs.pk, KPj.pk, msg);
        clock_gettime(CLOCK_REALTIME, &finish);
        results[offeset+i] = ns_difference(finish, start);
        printf("%lld,", ns_difference(finish, start));
        printf("%s,", b ? "OK" : "Bad");
        
        clock_gettime(CLOCK_REALTIME, &start);
        Report(aux, srm, sigma, msg, BSELECT, sig);
        clock_gettime(CLOCK_REALTIME, &finish);
        results[2*offeset+i] = ns_difference(finish, start);
        printf("%lld,", ns_difference(finish, start));
            
        clock_gettime(CLOCK_REALTIME, &start);
        bool b2 = Judge(pp, aux, KPj.sk, KPs.pk, KPr.pk, srm, sigma);
        clock_gettime(CLOCK_REALTIME, &finish);
        results[3*offeset+i] = ns_difference(finish, start);
        printf("%lld,", ns_difference(finish, start));
        printf("%s\n", b2 ? "Ok" : "Bad");
    }
  
    printf("%f %f %f %f\n", sum(results, offeset), sum(results+offeset, offeset), 
           sum(results+2*offeset, offeset), sum(results+3*offeset, offeset));
           
    // === Image Restoration Phase ===
    std::cout << "\n=== Image Restoration Phase ===" << std::endl;
    
    // Create selection mask for blocks
    std::vector<bool> selectedBlocks(numbers, false);
    int selectedCount = 0;
    for (int i = 0; i < numbers; ++i) {
        if (BSELECT[i] != -1) {
            selectedBlocks[i] = true;
            selectedCount++;
            std::cout << "Block " << i << ": Selected" << std::endl;
        }
    }
    std::cout << "Total selected blocks: " << selectedCount << "/" << numbers << std::endl;
    
    // Restore image using selected blocks
    std::cout << "Starting image restoration..." << std::endl;
    auto reconstructedImage = restoreImageFromPixels(
        mm, width, height, channels, rows, cols, selectedBlocks, FillMode::WHITE);
    
    std::cout << "Image restoration completed, size: " << reconstructedImage.size() << " bytes" << std::endl;
    
    // Save restored image
    std::string output_filename = "reconstructed_" + std::to_string(rows) + 
                                 "x" + std::to_string(cols) + "_" + std::to_string(t) + "blocks.jpg"; 
    
    std::cout << "Saving image to: " << output_filename << std::endl;
    if (stbi_write_jpg(output_filename.c_str(), width, height, channels, 
                       reconstructedImage.data(), 95)) {
        std::cout << "Restored image successfully saved!" << std::endl;
        std::cout << "Image dimensions: " << width << " x " << height << std::endl;
        
        // Calculate and display coverage percentage
        double coverage = (double)selectedCount / numbers * 100;
        std::cout << "Image coverage: " << coverage << "% (" << selectedCount << "/" << numbers << " blocks)" << std::endl;
    } else {
        std::cerr << "Failed to save restored image!" << std::endl;
    }
    
    // Cleanup resources
    mm.clear();
    delete[] message;
    delete[] BSELECT;
    
    std::cout << "Program execution completed!" << std::endl;
    return 0;
}
