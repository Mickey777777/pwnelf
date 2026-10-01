#pragma once

#include <cstdint>
#include <cstddef>

namespace pwnelf {
    using Elf64_Addr = std::uint64_t;
    using Elf64_Off = std::uint64_t;
    using Elf64_Half = std::uint16_t;
    using Elf64_Word = std::uint32_t;
    using Elf64_Xword = std::uint64_t;
    using Elf64_Sxword = std::int64_t;

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

    struct Elf64_Phdr{
        Elf64_Word p_type; // 세그먼트 종류 (PT_LOAD 등)
        Elf64_Word p_flags; // 권한 (PF_R/PF_W/PF_X)
        Elf64_Off p_offset; // 파일 오프셋
        Elf64_Addr p_vaddr; // 가상 주소
        Elf64_Addr p_paddr; // 물리 주소 (거의 vaddr 와 같음)
        Elf64_Xword p_filesz; // 파일에서 차지하는 크기
        Elf64_Xword p_memsz; // 메모리에서 차지하는 크기 (.bss 때문에 filesz 보다 클 수 있음)
        Elf64_Xword p_align; // 정렬
    };

    static_assert(sizeof(Elf64_Phdr) == 56, "Elf64_Phdr must be 56 bytes");
    static_assert(offsetof(Elf64_Phdr, p_flags) == 4, "");
    static_assert(offsetof(Elf64_Phdr, p_offset) == 8, "");
    static_assert(offsetof(Elf64_Phdr, p_vaddr) == 16, "");
    static_assert(offsetof(Elf64_Phdr, p_filesz) == 32, "");
    static_assert(offsetof(Elf64_Phdr, p_memsz) == 40, "");

    struct Elf64_Shdr{
        Elf64_Word sh_name; // .shstrtab 안에서의 이름 오프셋
        Elf64_Word sh_type; // 섹션 종류 (SHT_PROGBITS 등)
        Elf64_Xword sh_flags; // 속성 (SHF_ALLOC/SHF_EXECINSTR 등)
        Elf64_Addr sh_addr; // 로드됐을 때의 가상 주소
        Elf64_Off sh_offset; // 파일 오프셋 (SHT_NOBITS 면 무의미)
        Elf64_Xword sh_size; // 크기
        Elf64_Word sh_link; // 다른 섹션 인덱스 (용도는 sh_type 에 따라 다름)
        Elf64_Word sh_info; // 부가 정보 (용도는 sh_type 에 따라 다름)
        Elf64_Xword sh_addralign; // 정렬
        Elf64_Xword sh_entsize; // 고정 크기 항목 테이블일 때 항목 하나의 크기
    };

    static_assert(sizeof(Elf64_Shdr) == 64, "Elf64_Shdr must be 64 bytes");
    static_assert(offsetof(Elf64_Shdr, sh_type) == 4, "");
    static_assert(offsetof(Elf64_Shdr, sh_flags) == 8, "");
    static_assert(offsetof(Elf64_Shdr, sh_addr) == 16, "");
    static_assert(offsetof(Elf64_Shdr, sh_offset) == 24, "");
    static_assert(offsetof(Elf64_Shdr, sh_size) == 32, "");
    static_assert(offsetof(Elf64_Shdr, sh_link) == 40, "");
    static_assert(offsetof(Elf64_Shdr, sh_entsize) == 56, "");

    struct Elf64_Sym{
        Elf64_Word st_name;
        unsigned char st_info;
        unsigned char st_other;
        Elf64_Half st_shndx;
        Elf64_Addr st_value;
        Elf64_Xword st_size;
    };

    static_assert(sizeof(Elf64_Sym) == 24, "Elf64_Sym must be 24 bytes");
    static_assert(offsetof(Elf64_Sym, st_info) == 4, "");
    static_assert(offsetof(Elf64_Sym, st_other) == 5, "");
    static_assert(offsetof(Elf64_Sym, st_shndx) == 6, "");
    static_assert(offsetof(Elf64_Sym, st_value) == 8, "");
    static_assert(offsetof(Elf64_Sym, st_size) == 16, "");

    struct Elf64_Dyn{
        Elf64_Sxword d_tag;
        Elf64_Xword d_val;
    };

    struct Elf64_Rela{
        Elf64_Addr r_offset;
        Elf64_Xword r_info;
        Elf64_Sxword r_addend;
    };

    static_assert(sizeof(Elf64_Dyn) == 16, "Elf64_Dyn must be 16 bytes");
    static_assert(offsetof(Elf64_Dyn, d_val) == 8, "");

    static_assert(sizeof(Elf64_Rela) == 24, "Elf64_Rela must be 24 bytes");
    static_assert(offsetof(Elf64_Rela, r_info) == 8, "");
    static_assert(offsetof(Elf64_Rela, r_addend) == 16, "");

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

    // p_type — 세그먼트 종류
    inline constexpr Elf64_Word PT_NULL = 0;
    inline constexpr Elf64_Word PT_LOAD = 1;
    inline constexpr Elf64_Word PT_DYNAMIC = 2;
    inline constexpr Elf64_Word PT_INTERP = 3;
    inline constexpr Elf64_Word PT_NOTE = 4;
    inline constexpr Elf64_Word PT_PHDR = 6;
    inline constexpr Elf64_Word PT_TLS = 7;
    inline constexpr Elf64_Word PT_GNU_EH_FRAME = 0x6474e550;
    inline constexpr Elf64_Word PT_GNU_STACK = 0x6474e551;
    inline constexpr Elf64_Word PT_GNU_RELRO = 0x6474e552;

    // p_flags — 세그먼트 권한
    inline constexpr Elf64_Word PF_X = 1;
    inline constexpr Elf64_Word PF_W = 2;
    inline constexpr Elf64_Word PF_R = 4;

    // sh_type — 섹션 종류
    inline constexpr Elf64_Word SHT_NULL = 0;
    inline constexpr Elf64_Word SHT_PROGBITS = 1;
    inline constexpr Elf64_Word SHT_SYMTAB = 2;
    inline constexpr Elf64_Word SHT_STRTAB = 3;
    inline constexpr Elf64_Word SHT_RELA = 4;
    inline constexpr Elf64_Word SHT_DYNAMIC = 6;
    inline constexpr Elf64_Word SHT_NOTE = 7;
    inline constexpr Elf64_Word SHT_NOBITS = 8;
    inline constexpr Elf64_Word SHT_DYNSYM = 11;

    // sh_flags — 섹션 속성
    inline constexpr Elf64_Xword SHF_WRITE = 0x1;
    inline constexpr Elf64_Xword SHF_ALLOC = 0x2;
    inline constexpr Elf64_Xword SHF_EXECINSTR = 0x4;

    // 특수 섹션 인덱스
    inline constexpr Elf64_Half SHN_UNDEF = 0;

    // st_info 하위 4비트 — 심볼 종류
    inline constexpr unsigned char STT_NOTYPE = 0;
    inline constexpr unsigned char STT_OBJECT = 1;
    inline constexpr unsigned char STT_FUNC = 2;

    // st_info 상위 4비트 — 바인딩
    inline constexpr unsigned char STB_LOCAL = 0;
    inline constexpr unsigned char STB_GLOBAL = 1;
    inline constexpr unsigned char STB_WEAK = 2;

    // d_tag — 동적 엔트리 종류
    inline constexpr Elf64_Sxword DT_NULL = 0;
    inline constexpr Elf64_Sxword DT_NEEDED = 1;
    inline constexpr Elf64_Sxword DT_STRTAB = 5;
    inline constexpr Elf64_Sxword DT_STRSZ = 10;
    inline constexpr Elf64_Sxword DT_RPATH = 15;
    inline constexpr Elf64_Sxword DT_BIND_NOW = 24;
    inline constexpr Elf64_Sxword DT_RUNPATH = 29;
    inline constexpr Elf64_Sxword DT_FLAGS = 30;
    inline constexpr Elf64_Sxword DT_FLAGS_1 = 0x6ffffffb;

    // DT_FLAGS 값의 비트
    inline constexpr Elf64_Xword DF_BIND_NOW = 0x8;

    // DT_FLAGS_1 값의 비트
    inline constexpr Elf64_Xword DF_1_NOW = 0x1;
    inline constexpr Elf64_Xword DF_1_PIE = 0x08000000;

    // r_info 하위 32비트 — relocation 종류
    inline constexpr Elf64_Word R_X86_64_GLOB_DAT = 6;
    inline constexpr Elf64_Word R_X86_64_JUMP_SLOT = 7;
    inline constexpr Elf64_Word R_X86_64_IRELATIVE = 37;

    const char* machine_name(Elf64_Half machine);
}