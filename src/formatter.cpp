#include <string>
#include <cstdint>
// #include <cmath>
#include <algorithm>
#include <format>

namespace rfmstat {
std::string get_channel_rate_shades(const uint64_t& packets, const uint64_t length) {
    const std::string shades = " .-=+*FRM#"; // " ░▒▓" -- not supported by UTF-8 !
    const int NUM_SHADES = 10;
    const uint64_t MAX_BYTES_PER_SEC = 8000000;
    const int HALF_BAR_LENGTH = 10;
    
    double utilization_ratio = std::min(1.0, std::max(0.0, static_cast<double>(length) / MAX_BYTES_PER_SEC));
    double half_ratio = utilization_ratio / 2.0; 

    std::string right_side = "";

    for (int i = 0; i < HALF_BAR_LENGTH; ++i) {
        double segment_fill_ratio = std::max(0.0, std::min(1.0, (half_ratio * HALF_BAR_LENGTH) - i));
        int shade_index = static_cast<int>(segment_fill_ratio * NUM_SHADES);
        shade_index = std::min(shade_index, NUM_SHADES - 1);
        right_side += shades[shade_index];
    }

    std::string left_side = right_side;

    std::reverse(left_side.begin(), left_side.end());

    return left_side + right_side;
}


}