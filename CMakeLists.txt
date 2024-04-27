cmake_minimum_required(VERSION 3.10)

project(fss)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif ()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED on)

add_compile_options(-Wall -Wextra -g -Ofast)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

set(BUILD_SHARED_LIBS OFF)
set(DCMAKE_EXE_LINKER_FLAGS "-static")

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin)

set(INC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")

set(FSS_SRC_FILES
        include/fss/seal/uintarith.cpp
        include/fss/seal/smallmodulus.cpp
        include/fss/expandingprf.cpp
        include/fss/fsscontext.cpp
        include/fss/fssevaluator.cpp
        include/fss/fssgenerator.cpp
)

set(COMMON_SRC_FILES ${FSS_SRC_FILES})

add_executable(fss_example ${COMMON_SRC_FILES} src/fss_example.cpp)
target_link_libraries(fss_example PRIVATE OpenSSL::Crypto)
target_include_directories(fss_example PRIVATE ${INC_DIR})

add_library(fss ${FSS_SRC_FILES})
target_link_libraries(fss PRIVATE OpenSSL::Crypto)
target_include_directories(fss PUBLIC ${INC_DIR})

install(TARGETS fss
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib)

install(DIRECTORY ${INC_DIR}/fss
        DESTINATION include
        FILES_MATCHING PATTERN "*.hpp")
