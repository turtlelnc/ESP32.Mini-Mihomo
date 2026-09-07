cmake_minimum_required(VERSION 3.20)
project(clash_lite LANGUAGES CXX)

find_package(OpenSSL REQUIRED)

add_executable(mini-mihomo clash_lite.cpp)
target_compile_features(mini-mihomo PRIVATE cxx_std_17)
target_link_libraries(mini-mihomo PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_compile_definitions(mini-mihomo PRIVATE _DARWIN_C_SOURCE)
