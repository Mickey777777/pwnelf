#include <pwnelf/error.hpp>
#include <pwnelf/reader.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <limits>
#include <string>

namespace{
    const std::uint8_t kData[] = {
        0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
        'p',  'w',  'n',  'e',  'l',  'f',  0x00, 0xff,
    };

    const std::uint8_t kNoNul[] = {'a', 'b', 'c'};

    struct Pair{
        std::uint32_t a;
        std::uint32_t b;
    };

    pwnelf::Reader reader(){
        return pwnelf::Reader(pwnelf::ByteView(kData, sizeof(kData)));
    }
}

TEST(ReaderSlice, ReturnsRequestedWindow){
    const pwnelf::ByteView s = reader().slice(4, 4, "e_ident tail");
    EXPECT_EQ(s.size(), 4u);
    EXPECT_EQ(s.data(), kData + 4);
}

TEST(ReaderSlice, WholeBufferIsValid){
    const pwnelf::ByteView s = reader().slice(0, sizeof(kData), "file");
    EXPECT_EQ(s.size(), sizeof(kData));
}

TEST(ReaderSlice, EmptySliceAtEndIsValid){
    const pwnelf::ByteView s = reader().slice(sizeof(kData), 0, "tail");
    EXPECT_EQ(s.size(), 0u);
}

TEST(ReaderSlice, OnePastEndThrows){
    EXPECT_THROW(reader().slice(sizeof(kData), 1, "tail"), pwnelf::ParseError);
}

TEST(ReaderSlice, OffsetBeyondEndThrows){
    EXPECT_THROW(reader().slice(sizeof(kData) + 1, 0, "tail"), pwnelf::ParseError);
}

TEST(ReaderSlice, CountOverflowThrows){
    const std::uint64_t huge = std::numeric_limits<std::uint64_t>::max();
    EXPECT_THROW(reader().slice(sizeof(kData) - 1, huge, "section headers"), pwnelf::ParseError);
}

TEST(ReaderSlice, OffsetOverflowThrows){
    const std::uint64_t huge = std::numeric_limits<std::uint64_t>::max();
    EXPECT_THROW(reader().slice(huge, 1, "section headers"), pwnelf::ParseError);
}

TEST(ReaderSlice, ErrorMessageNamesTheStructure){
    try{
        reader().slice(100, 8, "program header table");
        FAIL() << "expected ParseError";
    }catch(const pwnelf::ParseError& e){
        EXPECT_NE(std::string(e.what()).find("program header table"), std::string::npos);
    }
}

TEST(ReaderRead, Byte){
    EXPECT_EQ(reader().read<std::uint8_t>(0, "magic"), 0x7f);
}

TEST(ReaderRead, HalfIsLittleEndian){
    EXPECT_EQ(reader().read<std::uint16_t>(0, "e_type"), 0x457f);
}

TEST(ReaderRead, WordIsLittleEndian){
    EXPECT_EQ(reader().read<std::uint32_t>(0, "magic"), 0x464c457fu);
}

TEST(ReaderRead, LastValidOffset){
    EXPECT_EQ(reader().read<std::uint8_t>(sizeof(kData) - 1, "last"), 0xff);
}

TEST(ReaderRead, StraddlingEndThrows){
    EXPECT_THROW(reader().read<std::uint32_t>(sizeof(kData) - 2, "e_shoff"), pwnelf::ParseError);
}

TEST(ReaderRead, TriviallyCopyableStruct){
    const Pair p = reader().read<Pair>(0, "pair");
    EXPECT_EQ(p.a, 0x464c457fu);
    EXPECT_EQ(p.b, 0x00010102u);
}

TEST(ReaderCstr, StopsAtNul){
    EXPECT_EQ(reader().cstr(8, 8, "section name"), "pwnelf");
}

TEST(ReaderCstr, EmptyStringWhenFirstByteIsNul){
    EXPECT_EQ(reader().cstr(14, 2, "section name"), "");
}

TEST(ReaderCstr, LimitIsClampedToBufferEnd){
    EXPECT_EQ(reader().cstr(8, 1000, "section name"), "pwnelf");
}

TEST(ReaderCstr, NoNulWithinLimitThrows){
    EXPECT_THROW(reader().cstr(0, 4, "section name"), pwnelf::ParseError);
}

TEST(ReaderCstr, NoNulBeforeBufferEndThrows){
    const pwnelf::Reader r(pwnelf::ByteView(kNoNul, sizeof(kNoNul)));
    EXPECT_THROW(r.cstr(0, 1000, "section name"), pwnelf::ParseError);
}

TEST(ReaderCstr, OffsetBeyondEndThrows){
    EXPECT_THROW(reader().cstr(sizeof(kData) + 1, 4, "section name"), pwnelf::ParseError);
}
