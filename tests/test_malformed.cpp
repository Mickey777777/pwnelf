#include <pwnelf/elf.hpp>
#include <pwnelf/elf_type.hpp>
#include <pwnelf/error.hpp>

#include <gtest/gtest.h>

#include "elf_fixture.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <random>
#include <string>
#include <utility>
#include <vector>

namespace{
    constexpr unsigned char kGlobalFunc = 0x12;
    constexpr std::uint32_t kSeed = 0xC0FFEE;
    constexpr int kRandomRounds = 2000;
    constexpr int kMaxFlipsPerRound = 16;
    constexpr std::size_t kTinyBufferMax = 4;
    constexpr std::size_t kAllocAlign = 16;

    std::vector<std::uint8_t> fullElf(){
        auto [symdata, strdata] = fixture::build_symtab({
            {"main", 0x401000, 0x20, kGlobalFunc, 1},
            {"printf", 0, 0, kGlobalFunc, 0},
        });
        const std::uint64_t runpath_off = strdata.size();
        const std::string runpath = "/opt/lib";
        strdata.insert(strdata.end(), runpath.begin(), runpath.end());
        strdata.push_back(0);

        fixture::ElfBuilder b;
        b.add_segment({pwnelf::PT_LOAD, pwnelf::PF_R | pwnelf::PF_X, 0, 0x400000, 0x800, 0x800, 0x1000, 0});
        b.add_segment({pwnelf::PT_GNU_STACK, pwnelf::PF_R | pwnelf::PF_W, 0, 0, 0, 0, 0x10, 0});
        b.add_segment({pwnelf::PT_GNU_RELRO, pwnelf::PF_R, 0, 0x403e00, 0x200, 0x200, 1, 0});
        b.add_section({".text", 1, 0x6, 0x401000, {0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3}, 0, 0, 0});
        b.add_section({".dynsym", 11, 0x2, 0x400300, symdata, 3, 1, fixture::kSymSize});
        b.add_section({".dynstr", 3, 0x2, 0x400400, strdata, 0, 0, 0});
        b.add_section({".rela.plt", 4, 0x42, 0x400500,
                       fixture::build_rela({{0x404018, pwnelf::R_X86_64_JUMP_SLOT, 2, 0}}),
                       2, 0, fixture::kRelaSize});
        b.add_section({".dynamic", 6, 0x3, 0x403e00,
                       fixture::build_dynamic({
                           {pwnelf::DT_BIND_NOW, 0},
                           {pwnelf::DT_FLAGS_1, pwnelf::DF_1_NOW},
                           {pwnelf::DT_RUNPATH, runpath_off},
                       }),
                       3, 0, fixture::kDynSize});
        return b.build();
    }

    void exerciseQueries(const pwnelf::ElfFile& elf){
        for(const pwnelf::Section& s : elf.sections()){
            elf.section_data(s);
        }
        elf.vaddr_to_offset(0x401000);
        elf.executable_segments();
        elf.function_at(0x401000);
        elf.find_function("main");
        elf.has_symbol("printf");
        elf.has_dynamic_tag(pwnelf::DT_BIND_NOW);
        elf.dynamic_value(pwnelf::DT_FLAGS_1);
        elf.dynamic_string(pwnelf::DT_RUNPATH);
        elf.got_symbol(0x404018);
    }

    void expectCleanOutcome(const std::vector<std::uint8_t>& buf, const std::string& what){
        const std::size_t padded = (buf.size() + kAllocAlign - 1) / kAllocAlign * kAllocAlign;
        std::vector<std::uint8_t> storage(padded);
        std::uint8_t* const begin = storage.data() + (padded - buf.size());
        std::copy(buf.begin(), buf.end(), begin);

        try{
            const pwnelf::ElfFile elf =
                pwnelf::ElfFile::parse(pwnelf::ByteView(begin, buf.size()), "<malformed>");
            exerciseQueries(elf);
        }catch(const pwnelf::Error&){
            return;
        }catch(const std::exception& e){
            FAIL() << what << ": threw non-pwnelf exception: " << e.what();
        }catch(...){
            FAIL() << what << ": threw a non-std exception";
        }
    }
}

TEST(Malformed, BaselineElfParsesCleanly){
    const std::vector<std::uint8_t> buf = fullElf();
    const pwnelf::ElfFile elf = pwnelf::ElfFile::parse(pwnelf::ByteView(buf.data(), buf.size()), "<ok>");

    EXPECT_EQ(elf.sections().size(), 7u);
    EXPECT_EQ(elf.segments().size(), 3u);
    EXPECT_TRUE(elf.has_symbol("main"));
    EXPECT_EQ(elf.got_symbol(0x404018), std::optional<std::string>{"printf"});
    EXPECT_EQ(elf.dynamic_string(pwnelf::DT_RUNPATH), std::optional<std::string>{"/opt/lib"});
}

TEST(Malformed, SurvivesTruncationAtEveryLength){
    const std::vector<std::uint8_t> full = fullElf();
    for(std::size_t len = 0; len < full.size(); ++len){
        const std::vector<std::uint8_t> truncated(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(len));
        expectCleanOutcome(truncated, "truncated to " + std::to_string(len));
    }
}

TEST(Malformed, SurvivesSingleByteCorruptionAnywhere){
    const std::vector<std::uint8_t> full = fullElf();
    for(std::size_t i = 0; i < full.size(); ++i){
        std::vector<std::uint8_t> buf = full;
        buf[i] = 0xff;
        expectCleanOutcome(buf, "byte " + std::to_string(i) + " set to 0xff");
    }
}

TEST(Malformed, SurvivesRandomMultiByteCorruption){
    const std::vector<std::uint8_t> full = fullElf();
    std::mt19937 rng(kSeed);
    std::uniform_int_distribution<std::size_t> pos(0, full.size() - 1);
    std::uniform_int_distribution<int> byte(0, 255);

    for(int round = 0; round < kRandomRounds; ++round){
        std::vector<std::uint8_t> buf = full;
        const int flips = 1 + (round % kMaxFlipsPerRound);
        for(int f = 0; f < flips; ++f){
            buf[pos(rng)] = static_cast<std::uint8_t>(byte(rng));
        }
        expectCleanOutcome(buf, "random round " + std::to_string(round));
    }
}

TEST(Malformed, SurvivesExtremeHeaderFieldValues){
    const std::vector<std::pair<std::size_t, std::uint64_t>> targets = {
        {fixture::kEhdrOffPhoff, 0xffffffffffffffffULL},
        {fixture::kEhdrOffPhoff, 0xfffffffffffff000ULL},
        {fixture::kEhdrOffShoff, 0xffffffffffffffffULL},
        {fixture::kEhdrOffShoff, 0x8000000000000000ULL},
        {fixture::kEhdrOffEntry, 0xffffffffffffffffULL},
    };
    for(const auto& [offset, value] : targets){
        std::vector<std::uint8_t> buf = fullElf();
        fixture::patch<std::uint64_t>(buf, offset, value);
        expectCleanOutcome(buf, "field at " + std::to_string(offset));
    }

    const std::vector<std::pair<std::size_t, std::uint16_t>> half_targets = {
        {fixture::kEhdrOffPhnum, 0xffff},
        {fixture::kEhdrOffShnum, 0xffff},
        {fixture::kEhdrOffShstrndx, 0xffff},
        {fixture::kEhdrOffPhentsize, 0xffff},
        {fixture::kEhdrOffShentsize, 0xffff},
        {fixture::kEhdrOffEhsize, 0},
    };
    for(const auto& [offset, value] : half_targets){
        std::vector<std::uint8_t> buf = fullElf();
        fixture::patch<std::uint16_t>(buf, offset, value);
        expectCleanOutcome(buf, "half field at " + std::to_string(offset));
    }
}

TEST(Malformed, SurvivesEmptyAndTinyBuffers){
    for(std::size_t len = 0; len <= kTinyBufferMax; ++len){
        const std::vector<std::uint8_t> buf(len, 0x7f);
        expectCleanOutcome(buf, "tiny buffer of " + std::to_string(len));
    }
}
