#pragma once

#include <pwnelf/bytes.hpp>

#include <cstring>
#include <string>
#include <type_traits>

namespace pwnelf{
    class Reader{
        private:
        ByteView data_;

        public:
        explicit Reader(ByteView data) noexcept: data_(data) {}

        std::size_t size() const noexcept {return data_.size();}
        ByteView all() const noexcept {return data_;}

        bool inRange(std::uint64_t offset, std::uint64_t count) const noexcept{
            const std::uint64_t n = data_.size();
            if(offset > n) return false;
            if(n-offset >= count) return true;
            return false;
        }

        ByteView slice(std::uint64_t offset, std::uint64_t count, const char* what) const;

        template <class T>
        T read(std::uint64_t offset, const char* what) const {
            static_assert(std::is_trivially_copyable<T>:: value, "read<T> requires trivially copyable T");
            const ByteView s = slice(offset, sizeof(T), what);
            T value{};
            std::memcpy(&value, s.data(), sizeof(T));
            return value;
        }

        std::string cstr(std::uint64_t offset, std::uint64_t limit, const char* what) const;
    };
}