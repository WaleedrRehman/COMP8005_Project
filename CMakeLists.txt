cmake_minimum_required(VERSION 3.10)
project(COMP8005_Assign_3)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Enable OpenMP
find_package(OpenMP REQUIRED)
if(OpenMP_CXX_FOUND)
    message(STATUS "OpenMP found, enabling parallel execution")
    add_compile_options(${OpenMP_CXX_FLAGS})
    add_link_options(${OpenMP_CXX_FLAGS})
endif()

# Add executable
add_executable(COMP8005_Assign_3 node.cpp
        node_worker.cpp
        server.cpp
        Message.cpp)

# Link OpenMP and libcrypt
target_link_libraries(COMP8005_Assign_3 PRIVATE OpenMP::OpenMP_CXX crypt)
