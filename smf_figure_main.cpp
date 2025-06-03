#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "smf_ecdsa.hpp"
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
 * @brief Split the image and return all blocks in contiguous memory
 * @param inputPath Input image path
 * @param[out] width Output image width
 * @param[out] height Output image height
 * @param[out] channels Output number of channels
 * @param rows Number of rows
 * @param cols Number of columns
 * @return std::vector<unsigned char> Contiguously stored data of all blocks
 */
 
std::vector<unsigned char> cropToDivisible(
    const unsigned char* data,
    int width, int height, int channels,
    int rows, int cols) 
{
    // Compute new size (floor)  
    const int newWidth = (width / cols) * cols;
    const int newHeight = (height / rows) * rows;
    
    if (newWidth <= 0 || newHeight <= 0) {
        throw std::runtime_error("Image too small for the grid");
    }

    // Crop image by copying the valid area
    std::vector<unsigned char> cropped(newWidth * newHeight * channels);
    for (int y = 0; y < newHeight; ++y) {
        const unsigned char* src = data + y * width * channels;
        unsigned char* dst = cropped.data() + y * newWidth * channels;
        std::copy_n(src, newWidth * channels, dst);
    }

    return cropped;
}



std::vector<unsigned char> gridSplitImage(
    const char* inputPath,
    int& width,
    int& height,
    int& channels,
    int rows,
    int cols)
{
   // 1. Load source image
    unsigned char* data = stbi_load(inputPath, &width, &height, &channels, 0);
    if (!data) {
        throw std::runtime_error("Failed to load image: " + std::string(stbi_failure_reason()));
    }

    // 2. Modify size to be exactly divisible
    auto cropped = cropToDivisible(data, width, height, channels, rows, cols);
    stbi_image_free(data);

    // Apply the new resized dimensions
    width = (width / cols) * cols;
    height = (height / rows) * rows;

    // 3. Determine block size
    const int tileW = width / cols;
    const int tileH = height / rows;
    const size_t tileSize = tileW * tileH * channels;

    // 4. Reserve memory for complete tiled data
    std::vector<unsigned char> buffer(rows * cols * tileSize);

    // 5. Process image partitioning
    for (int y = 0; y < rows; ++y) {
        for (int x = 0; x < cols; ++x) {
            const size_t tileOffset = (y * cols + x) * tileSize;
            
            // Copy pixel data to destination
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
 * @brief Calculate the average color
 */
void calculateAverageColor(const std::vector<unsigned char>& tiles,
                          int tileSize,
                          int channels,
                          unsigned char avgColor[4]) 
{
    size_t totalPixels = 0;
    memset(avgColor, 0, 4);
    
    for (size_t i = 0; i < tiles.size(); i += tileSize) {
        for (size_t p = 0; p < tileSize; p += channels) {
            for (int c = 0; c < channels; ++c) {
                avgColor[c] += tiles[i + p + c];
            }
            totalPixels++;
        }
    }
    
    if (totalPixels > 0) {
        for (int c = 0; c < channels; ++c) {
            avgColor[c] /= totalPixels;
        }
    } else {
        // Default color: gray
        for (int c = 0; c < channels; ++c) {
            avgColor[c] = 128;
        }
        if (channels == 4) avgColor[3] = 255;
    }
}

/**
 * @brief Reconstruct image from tiled data (with missing tile handling)
 * @param tiles Contiguous data of all tiles
 * @param tileWidth Width of each tile
 * @param tileHeight Height of each tile
 * @param channels Number of channels
 * @param gridRows Number of tile rows
 * @param gridCols Number of tile columns
 * @param available Array marking available tiles
 * @param mode Fill mode for missing tiles
 * @return Reconstructed image data
 */
 

std::vector<unsigned char> restoreImage(
    const std::vector<unsigned char>& tiles,
    int tileWidth, int tileHeight, int channels,
    int gridRows, int gridCols,
    const std::vector<bool>& available,
    FillMode mode = FillMode::BLACK) 
{
    // Check parameters
    if (available.size() != static_cast<size_t>(gridRows * gridCols)) {
        throw std::invalid_argument("Available tiles size mismatch");
    }

    const int imgWidth = tileWidth * gridCols;
    const int imgHeight = tileHeight * gridRows;
    std::vector<unsigned char> result(imgWidth * imgHeight * channels, 0);

    // Preprocessing: Calculate average color
    unsigned char avgR = 128, avgG = 128, avgB = 128, avgA = 255;
    if (mode == FillMode::AVERAGE || mode == FillMode::NEAREST) {
        unsigned char avgColor[4] = {0};
        calculateAverageColor(tiles, tileWidth * tileHeight * channels, channels, avgColor);
        avgR = avgColor[0];
        avgG = channels > 1 ? avgColor[1] : avgR;
        avgB = channels > 2 ? avgColor[2] : avgG;
        avgA = channels > 3 ? avgColor[3] : 255;
    }

    size_t tileSize = tileWidth * tileHeight * channels;
    for (int y = 0; y < gridRows; ++y) {
        for (int x = 0; x < gridCols; ++x) {
            size_t tileIndex = y * gridCols + x;
            
            // Process valid tiles
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
                            result[dstPos + c] = tiles[srcPos + c];
                        }
                    }
                }
                continue;
            }
            
            // Process missing tiles
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
                                size_t centerPos = nearestOffset + 
                                                 (tileHeight/2 * tileWidth + tileWidth/2) * channels;
                                for (int c = 0; c < channels; ++c) {
                                    result[pos + c] = tiles[centerPos + c];
                                }
                            } else {
                                result[pos] = avgR;
                                if (channels > 1) result[pos + 1] = avgG;
                                if (channels > 2) result[pos + 2] = avgB;
                                if (channels > 3) result[pos + 3] = avgA;
                            }
                            break;
                        }
                            
                        case FillMode::CHECKERBOARD: {
                            // Checkerboard fill: determine color based on global position
                            bool isBlack = ((globalX/32 + globalY/32) % 2) == 0;
                            unsigned char val = isBlack ? 0 : 255;
                            for (int c = 0; c < channels; ++c) {
                                result[pos + c] = c == 3 ? 255 : val; // Maintain alpha channel value at 255
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
	int numbers = rows*cols;
	int width, height, channels;
    auto mm = gridSplitImage("figures/pexels-manon-thvnd-40702295-30973663.jpg", 
                        width, height, channels, atoi(argv[1]), atoi(argv[2]));   // 96.3kB
    //auto mm = gridSplitImage("figures/pexels-brunoscramgnon-596135.jpg", 
    //                     width, height, channels, atoi(argv[1]), atoi(argv[2]));  1MB
    
    
    uint8_t* seed = (uint8_t *)malloc(32);
    //uint8_t* output = (uint8_t *)malloc(640);
    uint8_t* output = (uint8_t *)malloc(MSIZE*32);
    //uint8_t mac[640];
    uint8_t mac[MSIZE*32];
    int index[t+1];
    for(int i = 0; i < MSIZE+1; i++) {
		BSELECT[i] = -1;
	}
    
    unsigned char* msg = mm.data();
    if (!msg) return -1;
    FSIZE = mm.size();
    //MSIZE = 4;
    BSIZE = FSIZE / MSIZE;
    //printf("%d %d\n", FSIZE, BSIZE);
    
    PP pp;
    Setup(pp);
    KeyPair KPs = KG(pp);
    KeyPair KPr = KG(pp);
    KeyPair KPj = KG(pp);
    
    mcl::bn::Fp12 e1;
    mcl::bn::pairing(e1, KPr.pk.P, KPj.pk.Q);
    mcl::bn::Fp12::pow(e1, e1, KPs.sk.x2);
    
    // BLS12_381 576 Byte, BN254 384 Byte
    static unsigned char eStr[600];
    int l = e1.serialize(eStr, 600);
    
    Sig sig;
    Sigma sigma;
    //sig.seed = (uint8_t*)malloc(32*sizeof(uint8_t));
    sig.seed = seed;
   
    //e1.serialize(eStr, 600);
    //static const unsigned char*STRE; 
    STRE = (const unsigned char*)eStr; 
    uint8_t hm[600+32*MSIZE];
    uint8_t kf[MSIZE*32];
    uint8_t* message = new uint8_t[BSIZE*t+1];
    if(!message) {
		printf("bad");
		return -1;
	}
    //uint8_t kf[640];
    //int index[20];
	Srm srm;
	srm.m = message; srm.kf = kf; srm.index = index;
	// Default set
	for(int i = 0; i < t; i++) {
		BSELECT[i] = i;
	}
	printf("frank,verify,pass?,report,judge,pass?\n");

	int offeset = 1000;
	double results[4*offeset];
	double result = 0;
	Aux aux;  aux.key = output; aux.mac = mac; aux.hm = hm;
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
		Report(aux, srm,sigma, msg, BSELECT, sig);
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
  
	printf("%f %f %f %f\n", sum(results, offeset), sum(results+offeset, offeset), sum(results+2*offeset, offeset), 
	          sum(results+3*offeset, offeset));
 
 
    //int numbers = rows*cols;
    std::vector<bool> available(numbers, false);
    std::vector<unsigned char> vec(width*height*channels, 0);
    for (int i = 0; i < numbers; ++i) {
		if(BSELECT[i] != -1) {
			std::copy(srm.m + i*BSIZE, srm.m +(i+1)*BSIZE, vec.begin() + i*BSIZE);
			available[i] = true;
			//available[i]=true;
		}
		else {
			break;
		}
	}
	
	
	/*
	 *  Kitty's privacy-preserved image
	 * ./smf_figure_main 4 2 2
	 * for (int i = 0; i < numbers; ++i) {
		    available[i] = true;
	 *  }
	 * available[5] = false;
	 * available[8] = false;
	*/
	mm.clear();
	delete[]  message;
	delete[]  BSELECT;
	int tileWidth = width / cols;
    int tileHeight = height / rows;
    auto reconstructed = restoreImage(
            mm, tileWidth, tileHeight, channels,
            rows, cols, available, FillMode::WHITE);
        
   
    std::string output_filename = "output.jpg";
    output_filename = "reconstructed_" + std::to_string(rows) + std::to_string(cols) + "_" + std::to_string(t) + ".jpg"; 
    stbi_write_jpg(output_filename.c_str(), width, height, channels, 
                      reconstructed.data(), width*channels);
	
	
}


