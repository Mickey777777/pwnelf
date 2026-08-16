#include <pwnelf/lookup.hpp>
#include <pwnelf/pattern.hpp>

#include <stdexcept>
#include <optional>
#include <string>

namespace pwnelf{
    std::optional<std::size_t> lookupOffset(std::string arg){
        if(arg.rfind("0x", 0) != 0){
            return cyclic_find(std::string(arg));
        }

        std::string digit = arg.substr(2);
        std::size_t digit_len = digit.length();

        if(digit_len % 2 == 1){
            throw std::invalid_argument("hex value has an odd number of digits: " + std::string(arg));
        }else if(digit_len == 0){
            throw std::invalid_argument("hex value has no digits: " + std::string(arg));
        }else if(digit.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos){
            throw std::invalid_argument("hex value has non hex character: " + std::string(arg));
        }else if(digit_len != 8 && digit_len != 16){
            throw std::invalid_argument("hex value isn't 4 or 8 bytes: " + std::string(arg));
        }

        std::size_t width = digit_len/2;
        std::uint64_t value = std::stoull(digit, nullptr, 16);
        
        return cyclic_find(value, width);
    }
}