project(mkimplib LANGUAGES CXX)

add_executable(${PROJECT_NAME} ${PROJECT_NAME}.cpp)
target_link_libraries(${PROJECT_NAME} coffgen::coffgen libgenhelper::libgenhelper nlohmann_json::nlohmann_json)
