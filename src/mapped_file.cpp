#include <pwnelf/error.hpp>
#include <pwnelf/bytes.hpp>
#include <pwnelf/mapped_file.hpp>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>

namespace pwnelf{
    MappedFile::MappedFile(std::string path, ByteView data) noexcept
    : path_(std::move(path)), data_(data){
    }

    // double free 예방을 위한 이동 생성자
    MappedFile::MappedFile(MappedFile&& other) noexcept
    : path_(std::move(other.path_)), data_(other.data_){
        other.data_ = ByteView();
    }

    ByteView MappedFile::view() const noexcept{
        return data_;
    }

    const std::string& MappedFile::path() const noexcept{
        return path_;
    }

    MappedFile& MappedFile::operator=(MappedFile&& other) noexcept{
        if(this == &other){
            return *this;
        }

        this->reset();
        this->path_ = std::move(other.path_);
        this->data_ = other.view();

        other.data_ = ByteView();

        return *this;
    }

    MappedFile MappedFile::open(const std::string& path){
        const int fd = ::open(path.c_str(), O_RDONLY | O_NONBLOCK);
        if(fd == -1){
            throw IoError(path + ": " + std::strerror(errno));
        }

        struct stat st{};
        if(::fstat(fd, &st) == -1){
            const int err = errno;
            ::close(fd);
            throw IoError(path + ": " + std::strerror(err));
        }

        // 일반 파일이 아닌경우
        if(!S_ISREG(st.st_mode)){
            ::close(fd);
            throw IoError(path + ": not a regular file");
        }

        if(st.st_size == 0){
            ::close(fd);
            return MappedFile(path, ByteView());
        }

        void *mmaped = ::mmap(nullptr, static_cast<std::size_t>(st.st_size), PROT_READ, MAP_PRIVATE, fd, 0);
        const int err = errno;
        ::close(fd);

        if(mmaped == MAP_FAILED){
            throw IoError(path + ": mmap failed: " + std::strerror(err));
        }

        return MappedFile(path, ByteView(static_cast<const std::uint8_t*>(mmaped), static_cast<std::size_t>(st.st_size)));
    }

    void MappedFile::reset() noexcept{
        if(data_.data() != nullptr){ // 실제 매핑이 있는경우
            ::munmap(const_cast<std::uint8_t*>(data_.data()), data_.size()); // 커널에 매핑 반납
        }

        data_ = ByteView();
        path_.clear();
    }

    MappedFile::~MappedFile(){
        reset();
    }
}
