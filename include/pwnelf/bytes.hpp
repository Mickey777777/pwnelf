#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>

namespace pwnelf{
    class ByteView{
        private:
        const std::uint8_t* data_;
        std::size_t size_;

        public:
        ByteView() noexcept: data_(nullptr), size_(0) {}
        ByteView(const std::uint8_t* data, std::size_t size) noexcept
        : data_(data), size_(size) {}

        const std::uint8_t* data() const noexcept {return data_;}
        std::size_t size() const noexcept {return size_;}
        bool empty() const noexcept {return size_ == 0;}

        const std::uint8_t& operator[](std::size_t i) const {
            assert(i < size_);
            return data_[i];
        }

        ByteView subview(std::size_t offset, std::size_t count) const {
            assert(offset <= size_ && count <= size_ - offset);

            ByteView newByteView(data_ + offset, count);
            return newByteView;
        }

        const std::uint8_t* begin() const noexcept {return data_;}
        const std::uint8_t* end() const noexcept {return data_+size_;}
    };
}