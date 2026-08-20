include(FetchContent)
FetchContent_Declare(googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.15.2
)
FetchContent_MakeAvailable(googletest)

add_executable(pwnelf_tests
  test_pattern.cpp
  test_lookup.cpp
  test_reader.cpp
)
target_link_libraries(pwnelf_tests PRIVATE pwnelf_core GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(pwnelf_tests)

function(add_cli_output_test name expected)
  add_test(NAME ${name} COMMAND $<TARGET_FILE:pwnelf> ${ARGN})
  set_tests_properties(${name} PROPERTIES PASS_REGULAR_EXPRESSION "${expected}")
endfunction()

function(add_cli_exit_test name code)
  string(REPLACE ";" " " args "${ARGN}")
  add_test(NAME ${name}
           COMMAND sh -c "$<TARGET_FILE:pwnelf> ${args} >/dev/null 2>&1; test $? -eq ${code}")
endfunction()

add_cli_output_test(cli_cyclic_generate       "^aaaabaaacaaadaaaeaaaf\n$"  cyclic 21)
add_cli_output_test(cli_cyclic_lookup_string  "^4\n$"   cyclic --lookup baaa)
add_cli_output_test(cli_cyclic_lookup_hex32   "^4\n$"   cyclic --lookup 0x61616162)
add_cli_output_test(cli_cyclic_lookup_hex64   "^0\n$"   cyclic --lookup 0x6161616261616161)

add_cli_exit_test(cli_lookup_not_found      1  cyclic --lookup ZZZZ)
add_cli_exit_test(cli_lookup_nul_bytes      1  cyclic --lookup 0x00000000)
add_cli_exit_test(cli_hex_odd_digits        2  cyclic --lookup 0xabc)
add_cli_exit_test(cli_hex_no_digits         2  cyclic --lookup 0x)
add_cli_exit_test(cli_hex_non_hex_char      2  cyclic --lookup 0xzz)
add_cli_exit_test(cli_hex_bad_width         2  cyclic --lookup 0x6162)
add_cli_exit_test(cli_length_too_large      2  cyclic 999999999)
add_cli_exit_test(cli_length_missing        2  cyclic)

add_test(NAME cli_no_subcommand COMMAND $<TARGET_FILE:pwnelf>)
set_tests_properties(cli_no_subcommand PROPERTIES WILL_FAIL TRUE)

add_test(NAME cli_mutually_exclusive COMMAND $<TARGET_FILE:pwnelf> cyclic 21 --lookup baaa)
set_tests_properties(cli_mutually_exclusive PROPERTIES WILL_FAIL TRUE)

add_test(NAME cli_error_goes_to_stderr_only
         COMMAND sh -c "test -z \"$($<TARGET_FILE:pwnelf> cyclic --lookup ZZZZ 2>/dev/null)\"")
