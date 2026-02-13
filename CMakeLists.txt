cmake_minimum_required(VERSION 3.15)
project(rfmstat VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

if(NOT EXISTS "${PROJECT_SOURCE_DIR}/third_party/CLI11/CMakeLists.txt")
    message(FATAL_ERROR "CLI11 submodule is missing! Run: git submodule update --init --recursive")
endif()

add_subdirectory(third_party/CLI11)

find_package(PkgConfig REQUIRED)

pkg_check_modules(PCAP REQUIRED libpcap)
pkg_check_modules(LIBNL REQUIRED libnl-3.0 libnl-genl-3.0)

find_package(Threads REQUIRED)

configure_file(
    "include/rfmstat/version.hpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/rfmstat/version.hpp"
)

add_executable(${PROJECT_NAME} 
    src/main.cpp 
    src/sniffer.cpp
    src/utils.cpp
    src/iface_device.cpp
    src/formatter.cpp
)

target_include_directories(${PROJECT_NAME} PRIVATE 
    include 
    ${PCAP_INCLUDE_DIRS}
    ${LIBNL_INCLUDE_DIRS}
    "${CMAKE_CURRENT_BINARY_DIR}/generated"
)

target_link_libraries(${PROJECT_NAME} PRIVATE 
    CLI11::CLI11
    ${PCAP_LIBRARIES}
    ${LIBNL_LIBRARIES}
    Threads::Threads
)

target_link_options(${PROJECT_NAME} PRIVATE ${PCAP_LDFLAGS} ${LIBNL_LDFLAGS})

install(TARGETS ${PROJECT_NAME} DESTINATION bin)

install(FILES man/rfmstat.1 
        DESTINATION share/man/man1)

install(FILES man/rfmstat.ru.1 
        DESTINATION share/man/ru/man1 
        RENAME rfmstat.1)