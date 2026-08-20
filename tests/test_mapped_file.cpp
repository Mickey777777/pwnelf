#include <pwnelf/error.hpp>
#include <pwnelf/mapped_file.hpp>

#include <gtest/gtest.h>

#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>
#include <fstream>
#include <memory>
#include <string>
#include <type_traits>

namespace{
    const std::string kContent = "\x7f" "ELF\x02\x01\x01\x00 payload";

    std::string tmpPath(const std::string& name){
        return std::string(PWNELF_TEST_TMPDIR) + "/" + name;
    }

    std::string writeFile(const std::string& name, const std::string& content){
        const std::string path = tmpPath(name);
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        f.write(content.data(), static_cast<std::streamsize>(content.size()));
        f.close();
        return path;
    }

    std::string makeDir(const std::string& name){
        const std::string path = tmpPath(name);
        ::mkdir(path.c_str(), 0755);
        return path;
    }
}

TEST(MappedFile, ExposesFileSize){
    const std::string path = writeFile("regular.bin", kContent);
    const pwnelf::MappedFile m = pwnelf::MappedFile::open(path);
    EXPECT_EQ(m.view().size(), kContent.size());
}

TEST(MappedFile, ViewMatchesFileBytes){
    const std::string path = writeFile("regular.bin", kContent);
    const pwnelf::MappedFile m = pwnelf::MappedFile::open(path);
    const pwnelf::ByteView v = m.view();
    ASSERT_EQ(v.size(), kContent.size());
    for(std::size_t i = 0; i < v.size(); ++i){
        EXPECT_EQ(v[i], static_cast<std::uint8_t>(kContent[i])) << "byte " << i;
    }
}

TEST(MappedFile, RemembersPath){
    const std::string path = writeFile("regular.bin", kContent);
    const pwnelf::MappedFile m = pwnelf::MappedFile::open(path);
    EXPECT_EQ(m.path(), path);
}

TEST(MappedFile, EmptyFileBecomesEmptyView){
    const std::string path = writeFile("empty.bin", "");
    const pwnelf::MappedFile m = pwnelf::MappedFile::open(path);
    EXPECT_EQ(m.view().size(), 0u);
    EXPECT_TRUE(m.view().empty());
}

TEST(MappedFile, MissingFileThrowsIoError){
    EXPECT_THROW(pwnelf::MappedFile::open(tmpPath("no_such_file.bin")), pwnelf::IoError);
}

TEST(MappedFile, DirectoryThrowsIoError){
    const std::string path = makeDir("a_directory");
    EXPECT_THROW(pwnelf::MappedFile::open(path), pwnelf::IoError);
}

TEST(MappedFile, ErrorMessageNamesThePath){
    const std::string path = tmpPath("no_such_file.bin");
    try{
        pwnelf::MappedFile::open(path);
        FAIL() << "expected IoError";
    }catch(const pwnelf::IoError& e){
        EXPECT_NE(std::string(e.what()).find(path), std::string::npos);
    }
}

TEST(MappedFile, MoveConstructionKeepsMappingAlive){
    const std::string path = writeFile("regular.bin", kContent);
    std::unique_ptr<pwnelf::MappedFile> src(
        new pwnelf::MappedFile(pwnelf::MappedFile::open(path)));

    pwnelf::MappedFile dst(std::move(*src));
    src.reset();

    ASSERT_EQ(dst.view().size(), kContent.size());
    EXPECT_EQ(dst.view()[0], 0x7f);
    EXPECT_EQ(dst.path(), path);
}

TEST(MappedFile, MoveAssignmentKeepsMappingAlive){
    const std::string path = writeFile("regular.bin", kContent);
    const std::string other = writeFile("other.bin", "xx");

    pwnelf::MappedFile dst = pwnelf::MappedFile::open(other);
    std::unique_ptr<pwnelf::MappedFile> src(
        new pwnelf::MappedFile(pwnelf::MappedFile::open(path)));

    dst = std::move(*src);
    src.reset();

    ASSERT_EQ(dst.view().size(), kContent.size());
    EXPECT_EQ(dst.view()[0], 0x7f);
}

TEST(MappedFile, IsMovableButNotCopyable){
    static_assert(std::is_move_constructible<pwnelf::MappedFile>::value,
                  "MappedFile must be move constructible");
    static_assert(std::is_move_assignable<pwnelf::MappedFile>::value,
                  "MappedFile must be move assignable");
    static_assert(!std::is_copy_constructible<pwnelf::MappedFile>::value,
                  "MappedFile must not be copy constructible");
    static_assert(!std::is_copy_assignable<pwnelf::MappedFile>::value,
                  "MappedFile must not be copy assignable");
}

TEST(MappedFile, FifoDoesNotBlock){
    const std::string path = tmpPath("a_fifo");
    ::unlink(path.c_str());
    ASSERT_EQ(::mkfifo(path.c_str(), 0644), 0);

    ::alarm(5);
    EXPECT_THROW(pwnelf::MappedFile::open(path), pwnelf::IoError);
    ::alarm(0);
}
