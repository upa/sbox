cmake_minimum_required(VERSION 3.1)

project(sbox)

set(CMAKE_C_FLAGS "-Wall -O -g")

# sboxd
add_executable(sboxd src/sboxd.c)
target_include_directories(sboxd PUBLIC ./include)
target_link_libraries(sboxd seccomp pthread) 

# sbox
add_executable(sbox src/sbox.c)
target_include_directories(sbox PUBLIC ./include)
target_link_libraries(sbox seccomp)
