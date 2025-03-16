cmake_minimum_required(VERSION 3.10)

project(implibgen)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

enable_testing()

add_subdirectory(ThirdParty/nlohmann_json)

add_subdirectory(CoffGen)
add_subdirectory(ImpGen)
add_subdirectory(ImpLibFix)
add_subdirectory(LibGen)
add_subdirectory(LibGenHelper)
add_subdirectory(mkimplib)
add_subdirectory(dumpsyms)
