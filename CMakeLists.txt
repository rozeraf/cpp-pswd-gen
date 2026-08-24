cmake_minimum_required(VERSION 3.16)

if(NOT DEFINED CMAKE_CXX_COMPILER)
    find_program(CLANGXX_EXECUTABLE NAMES clang++ REQUIRED)
    set(CMAKE_CXX_COMPILER "${CLANGXX_EXECUTABLE}" CACHE FILEPATH "C++ compiler")
endif()

project(cpp_pswd_gen LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(cpp_pswd_gen main.cpp)
target_link_libraries(cpp_pswd_gen PRIVATE OpenSSL::Crypto)
target_compile_definitions(cpp_pswd_gen PRIVATE
    DICEWARE_WORDLIST_PATH="${CMAKE_CURRENT_SOURCE_DIR}/data/eff_large_wordlist.txt")

add_custom_command(TARGET cpp_pswd_gen POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:cpp_pswd_gen>/data"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/data/eff_large_wordlist.txt"
            "$<TARGET_FILE_DIR:cpp_pswd_gen>/data/eff_large_wordlist.txt")
