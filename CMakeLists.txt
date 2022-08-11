cmake_minimum_required(VERSION 3.1)

project(mnbn)

set(CMAKE_C_FLAGS "-Wall -O -g")

# mnbnd
add_executable(mnbnd src/mnbnd.c)
target_include_directories(mnbnd PUBLIC ./include)
target_link_libraries(mnbnd seccomp pthread) 

# mnbn
add_executable(mnbn src/mnbn.c)
target_include_directories(mnbn PUBLIC ./include)
target_link_libraries(mnbn seccomp)
