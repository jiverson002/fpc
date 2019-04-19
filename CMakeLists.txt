cmake_minimum_required(VERSION 3.0)

# CMake version 3.0 introduced the VERSION option of the project() command to
# specify a project version as well as the name
cmake_policy(SET CMP0048 NEW)

# Mark the language as C so that CMake doesn't try to test the C++
# cross-compiler's ability to compile a simple program because that will fail
project(fpc VERSION 1.0.0 LANGUAGES C)

# Build libfpc
add_library(fpc
  src/fpc.c
)
