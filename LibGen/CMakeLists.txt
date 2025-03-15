project(libgen LANGUAGES CXX)

add_library(${PROJECT_NAME} STATIC LibImpl.cpp)
add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${PROJECT_NAME} coffgen::coffgen)

add_executable(test_${PROJECT_NAME} test_${PROJECT_NAME}.cpp)
target_link_libraries(test_${PROJECT_NAME} ${PROJECT_NAME}::${PROJECT_NAME} impgen::impgen)

add_test(
    NAME test_${PROJECT_NAME}
    COMMAND $<TARGET_FILE:test_${PROJECT_NAME}>)
