project(libgenhelper LANGUAGES CXX)

add_library(${PROJECT_NAME} STATIC LibGenHelperImpl.cpp)
add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${PROJECT_NAME} coffgen::coffgen libgen::libgen impgen::impgen)
