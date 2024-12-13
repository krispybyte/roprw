cmake_minimum_required(VERSION 3.16)

project(roprw LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

file(GLOB_RECURSE SOURCES "src/*.cpp")
file(GLOB_RECURSE HEADERS "include/*.h" "include/*.hpp")

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

include_directories(${CMAKE_SOURCE_DIR})

target_link_libraries(${PROJECT_NAME} PRIVATE ntdll)