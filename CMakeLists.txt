cmake_minimum_required(VERSION 3.10)
project(COMP8005_Project)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)


# Add executable
add_executable(COMP8005_Project
        Message.cpp
        Message.h
        controller.cpp
#        node.cpp
)

# Link libcrypt
target_link_libraries(COMP8005_Project PRIVATE crypt)
