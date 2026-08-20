#include <pwnelf/bytes.hpp>
#include <pwnelf/reader.hpp>
#include <pwnelf/error.hpp>
#include <pwnelf/hexfmt.hpp>

#include <string>
#include <algorithm>

namespace pwnelf{
    ByteView Reader::slice(std::uint64_t offset, std::uint64_t count, const char* what) const {
        if(!Reader::inRange(offset, count)){
            throw ParseError(std::string(what) + ": out of bounds read at " + hex(offset) + " (" + hex(count) + " bytes, file size " + hex(size()) + ")");
        }

        return data_.subview(offset, count);
    }

    std::string Reader::cstr(std::uint64_t offset, std::uint64_t limit, const char* what) const {
        if(!inRange(offset, 0)){
            throw ParseError(std::string(what) + ": offset " + hex(offset) + " past end of file (size " + hex(size()) + ")");
        }

        limit = std::min(limit, size()-offset);
        ByteView bv = slice(offset, limit, what);

        for(std::size_t i=0; i<bv.size(); ++i){
            if(bv[i] == 0){
                return std::string(bv.begin(), bv.begin() + i);
            }
        }

        throw ParseError(std::string(what) + ": unterminated string at " + hex(offset) + " (scanned " + hex(limit) + " bytes)");
    }
}