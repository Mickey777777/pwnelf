cmake_minimum_required(VERSION 3.20)
project(pwnelf LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(PWNELF_SANITIZE "Enable UBSan and libc++ hardening" OFF)
if(PWNELF_SANITIZE)
  add_compile_options(-fsanitize=undefined -fno-omit-frame-pointer -g)
  add_compile_definitions(_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_DEBUG)
  add_link_options(-fsanitize=undefined)
endif()

add_library(pwnelf_core STATIC
  src/pattern.cpp
)
target_include_directories(pwnelf_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(pwnelf_core PRIVATE -Wall -Wextra -Wpedantic)

add_executable(pwnelf src/main.cpp)
target_link_libraries(pwnelf PRIVATE pwnelf_core)
target_compile_options(pwnelf PRIVATE -Wall -Wextra -Wpedantic)

enable_testing()
add_subdirectory(tests)
