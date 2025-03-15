cmake_minimum_required(VERSION 3.10)

project(ImpLibGenerator)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

enable_testing()

add_subdirectory(CoffGen)
add_subdirectory(ImpGen)
add_subdirectory(ImpLibFix)
add_subdirectory(LibGen)
add_subdirectory(LibGenHelper)
add_subdirectory(MakeImpLib)
add_subdirectory(dll2def)
