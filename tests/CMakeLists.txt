include(FetchContent)
FetchContent_Declare(googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.15.2
)
FetchContent_MakeAvailable(googletest)

add_executable(pwnelf_tests
  test_pattern.cpp
)
target_link_libraries(pwnelf_tests PRIVATE pwnelf_core GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(pwnelf_tests)
