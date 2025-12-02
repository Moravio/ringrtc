cmake_minimum_required(VERSION 3.22.1)
project(FHE LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

add_library(fhe STATIC
    fhe.cpp
)

set(OPENFHE_LIBS_DIR "${CMAKE_SOURCE_DIR}/lib/${ANDROID_ABI}")

add_library(openfhe-core SHARED IMPORTED)
set_target_properties(openfhe-core PROPERTIES
    IMPORTED_LOCATION "${OPENFHE_LIBS_DIR}/libOPENFHEcore.so"
)

add_library(openfhe-pke SHARED IMPORTED)
set_target_properties(openfhe-pke PROPERTIES
    IMPORTED_LOCATION "${OPENFHE_LIBS_DIR}/libOPENFHEpke.so"
)

add_library(openfhe-binfhe SHARED IMPORTED)
set_target_properties(openfhe-binfhe PROPERTIES
    IMPORTED_LOCATION "${OPENFHE_LIBS_DIR}/libOPENFHEbinfhe.so"
)

target_include_directories(fhe PRIVATE
    ${CMAKE_SOURCE_DIR}/include/openfhe
    ${CMAKE_SOURCE_DIR}/include/openfhe/binfhe
    ${CMAKE_SOURCE_DIR}/include/openfhe/cereal
    ${CMAKE_SOURCE_DIR}/include/openfhe/core
    ${CMAKE_SOURCE_DIR}/include/openfhe/pke
)

target_link_libraries(fhe
    PRIVATE
        openfhe-binfhe
        openfhe-core
        openfhe-pke
)

install(TARGETS fhe
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
