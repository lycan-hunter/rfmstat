cmake_minimum_required(VERSION 3.15)
project(rfmstat VERSION 1.0 LANGUAGES CXX)

# Генерация compile_commands.json для работы IntelliSense в VS Code
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Стандарт C++20 (нужен для std::format)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Куда класть готовый бинарник
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

# 1. Подключаем CLI11 (аргументы командной строки)
add_subdirectory(third_party/CLI11)

# 2. Ищем libpcap через PkgConfig (стандарт для Arch/Asahi)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# 3. Ищем системную библиотеку потоков (нужна для std::thread)
find_package(Threads REQUIRED)

# 4. Создаем исполняемый файл
# ВАЖНО: здесь перечислены ОБА твоих .cpp файла
add_executable(${PROJECT_NAME} 
    src/main.cpp 
    src/sniffer.cpp
)

# 5. Настраиваем пути к инклудам (Headers)
target_include_directories(${PROJECT_NAME} PRIVATE 
    include 
    ${PCAP_INCLUDE_DIRS}
)

# 6. Линкуем все библиотеки
target_link_libraries(${PROJECT_NAME} PRIVATE 
    CLI11::CLI11
    ${PCAP_LIBRARIES}
    Threads::Threads  # Добавляет -lpthread автоматически
)

# Необязательно: если pcap_LDFLAGS содержит что-то важное
target_link_options(${PROJECT_NAME} PRIVATE ${PCAP_LDFLAGS})
