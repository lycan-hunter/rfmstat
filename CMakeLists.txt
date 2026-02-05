cmake_minimum_required(VERSION 3.15)
project(rfmstat VERSION 1.0 LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(third_party/CLI11)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

add_executable(${PROJECT_NAME} src/main.cpp)

target_link_libraries(${PROJECT_NAME} PRIVATE 
    CLI11::CLI11
    ${PCAP_LIBRARIES}
)

target_include_directories(${PROJECT_NAME} PRIVATE ${PCAP_INCLUDE_DIRS})
