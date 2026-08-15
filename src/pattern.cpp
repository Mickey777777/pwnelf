#include <pwnelf/pattern.hpp>

#include <iostream>
#include <string>
#include <cstddef>
#include <stdexcept>
#include <optional>
#include <cstdint>
#include <vector>

namespace pwnelf {

const std::string alphabet = "abcdefghijklmnopqrstuvwxyz";
const std::size_t maxLength = 456976;

namespace{
    struct DeBruijn{
        std::size_t k;
        std::size_t n;
        std::size_t limit;
        std::vector<std::size_t> a;
        std::string out;

        DeBruijn(std::size_t k_, std::size_t n_, std::size_t limit_)
        : k(k_), n(n_), limit(limit_), a(n_+1, 0){
            out.reserve(limit_);
        }

        void db(std::size_t t, std::size_t p){
            if(out.length() >= limit) return;

            if(t>n){
                if(n%p==0){
                    for(std::size_t i=1; i<=p; i++){
                        if(out.length() >= limit) return;
                        out += alphabet[a[i]];
                    }
                }
                return;
            }

            a[t] = a[t-p];
            db(t+1, p);

            for(std::size_t j=a[t-p]+1; j<=k-1; j++){
                if(out.length() >= limit) return;
                a[t] = j;
                db(t+1, t);
            }
        }
    };
}

std::string cyclic(std::size_t len){
    if(len > maxLength){
        throw std::length_error("cyclic: requested length exceeds (456976)");
    }

    DeBruijn db_(alphabet.size(), 4, len);
    db_.db(1, 1);
    return std::move(db_.out);
}

std::optional<std::size_t> cyclic_find(std::string query){
    if(query.empty()) return std::nullopt;

    static std::string full = cyclic(maxLength);
    std::size_t pos = full.find(query);

    if(pos == std::string::npos){
        return std::nullopt;
    }
    return pos;
}
std::optional<std::size_t> cyclic_find(std::uint64_t value, std::size_t width){
    std::string bytes;
    for(std::size_t i=0; i<width; i++){
        bytes.push_back(static_cast<char>(value >> (8*i) & 0xFF));
    }

    return cyclic_find(bytes);
}

}  // namespace pwnelf
