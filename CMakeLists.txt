cmake_minimum_required(VERSION 3.15)
project(rfmstat VERSION 1.0 LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

add_subdirectory(third_party/CLI11)

find_package(PkgConfig REQUIRED)
# Добавляем libnl-3.0 и libnl-genl-3.0 в поиск
pkg_check_modules(PCAP REQUIRED libpcap)
pkg_check_modules(LIBNL REQUIRED libnl-3.0 libnl-genl-3.0)

find_package(Threads REQUIRED)

# Добавляем IfaceDev.cpp в список сборки
add_executable(${PROJECT_NAME} 
    src/main.cpp 
    src/sniffer.cpp
    src/utils.cpp
    src/iface_device.cpp
    src/formatter.cpp
)

# Добавляем пути к заголовкам libnl
target_include_directories(${PROJECT_NAME} PRIVATE 
    include 
    ${PCAP_INCLUDE_DIRS}
    ${LIBNL_INCLUDE_DIRS}
)

# Линкуем libnl (подтянет и основной nl, и genl)
target_link_libraries(${PROJECT_NAME} PRIVATE 
    CLI11::CLI11
    ${PCAP_LIBRARIES}
    ${LIBNL_LIBRARIES}
    Threads::Threads
)

target_link_options(${PROJECT_NAME} PRIVATE ${PCAP_LDFLAGS} ${LIBNL_LDFLAGS})
