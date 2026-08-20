#pragma once

#include <string>
#include <cstdint>
#include <sstream>
#include <iomanip>

namespace pwnelf{
    inline std::string hex(std::uint64_t v){
        std::ostringstream oss;
        oss << "0x" <<std::hex << v;
        return oss.str();
    }

    inline std::string hex(std::uint64_t v, int width){
        std::ostringstream oss;
        oss << "0x" << std::setw(width) << std::setfill('0') << std::hex << v;
        return oss.str();
    }
}
