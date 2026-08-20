#pragma once

#include <cstdint>
#include <cstddef>

namespace pwnelf {
    using Elf64_Addr = std::uint64_t;
    using Elf64_Off = std::uint64_t;
    using Elf64_Half = std::uint16_t;
    using Elf64_Word = std::uint32_t;
    using Elf64_Xword = std::uint64_t;

    struct Elf64_Ehdr{
        unsigned char e_ident[16]; // 매직바이트, 클래스, 엔디안, 버전
        Elf64_Half e_type; // 파일 종류
        Elf64_Half e_machine; // CPU
        Elf64_Word e_version; // 파일 버전
        Elf64_Addr e_entry; // 엔트리 가상 주소
        Elf64_Off e_phoff; // 프로그램 헤더 테이블 파일 오프셋
        Elf64_Off e_shoff; // 섹션 헤더 테이블 파일 오프셋
        Elf64_Word e_flags; // 프로세서별 플래그
        Elf64_Half e_ehsize; // 헤더 크기
        Elf64_Half e_phentsize; // 프로그램 헤더 한 개 크기
        Elf64_Half e_phnum; // 프로그램 헤더 개수
        Elf64_Half e_shentsize; // 섹션 헤더 한 개 크기
        Elf64_Half e_shnum; // 섹션 헤더 개수
        Elf64_Half e_shstrndx; // 섹션 이름 문자열 테이블이 몇 번째 섹션인지
    };

    static_assert(sizeof(Elf64_Ehdr) == 64, "Elf64_Ehdr must be 64 bytes");
    static_assert(offsetof(Elf64_Ehdr, e_type) == 16, "");
    static_assert(offsetof(Elf64_Ehdr, e_machine) == 18, "");
    static_assert(offsetof(Elf64_Ehdr, e_entry) == 24, "");
    static_assert(offsetof(Elf64_Ehdr, e_phoff) == 32, "");
    static_assert(offsetof(Elf64_Ehdr, e_shoff) == 40, "");
    static_assert(offsetof(Elf64_Ehdr, e_ehsize) == 52, "");
    static_assert(offsetof(Elf64_Ehdr, e_phnum) == 56, "");
    static_assert(offsetof(Elf64_Ehdr, e_shnum) == 60, "");
    static_assert(offsetof(Elf64_Ehdr, e_shstrndx) == 62, "");

    // e_ident inner 인덱스
    inline constexpr std::size_t EI_MAG0 = 0;
    inline constexpr std::size_t EI_MAG1 = 1;
    inline constexpr std::size_t EI_MAG2 = 2;
    inline constexpr std::size_t EI_MAG3 = 3;
    inline constexpr std::size_t EI_CLASS = 4;
    inline constexpr std::size_t EI_DATA = 5;
    inline constexpr std::size_t EI_VERSION = 6;

    // 매직바이트 0x7f ELF
    inline constexpr unsigned char ELFMAG0 = 0x7f;
    inline constexpr unsigned char ELFMAG1 = 'E';
    inline constexpr unsigned char ELFMAG2 = 'L';
    inline constexpr unsigned char ELFMAG3 = 'F';

    // e_ident[EI_CLASS] — 32bit or 64bit
    inline constexpr unsigned char ELFCLASS32 = 1;
    inline constexpr unsigned char ELFCLASS64 = 2;

    // e_ident[EI_DATA] — 리틀 or 빅엔디언
    inline constexpr unsigned char ELFDATA2LSB = 1;
    inline constexpr unsigned char ELFDATA2MSB = 2;

    // e_ident[EI_VERSION], e_version
    inline constexpr unsigned char EV_CURRENT = 1;

    // e_type — 파일 종류
    inline constexpr Elf64_Half ET_NONE = 0;
    inline constexpr Elf64_Half ET_REL = 1;
    inline constexpr Elf64_Half ET_EXEC = 2;
    inline constexpr Elf64_Half ET_DYN = 3;
    inline constexpr Elf64_Half ET_CORE = 4;

    // e_machine — CPU
    inline constexpr Elf64_Half EM_386 = 3;
    inline constexpr Elf64_Half EM_ARM = 40;
    inline constexpr Elf64_Half EM_X86_64 = 62;
    inline constexpr Elf64_Half EM_AARCH64 = 183;
    inline constexpr Elf64_Half EM_RISCV = 243;
    

    // 검증용 크기
    inline constexpr Elf64_Half kEhdrSize = 64;
    inline constexpr Elf64_Half kPhdrSize = 56;
    inline constexpr Elf64_Half kShdrSize = 64;

    const char* machine_name(Elf64_Half machine);
}