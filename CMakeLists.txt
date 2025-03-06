cmake_minimum_required(VERSION 3.12)
project(pycdc)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Debug options.
option(ENABLE_BLOCK_DEBUG "Enable block debugging" OFF)
option(ENABLE_STACK_DEBUG "Enable stack debugging" OFF)

# Turn debug defs on if they're enabled.
if (ENABLE_BLOCK_DEBUG)
    add_definitions(-DBLOCK_DEBUG)
endif()
if (ENABLE_STACK_DEBUG)
    add_definitions(-DSTACK_DEBUG)
endif()

if(CMAKE_COMPILER_IS_GNUCXX OR "${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
    set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wno-error=shadow ${CMAKE_CXX_FLAGS}")
endif()

if(CMAKE_COMPILER_IS_GNUCXX)
    set(CMAKE_EXE_LINKER_FLAGS "-static -static-libgcc -static-libstdc++ ${CMAKE_EXE_LINKER_FLAGS}")
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_executable(pyarmor-1shot
    pyarmor-1shot.cpp
    ASTree.cpp
    ASTNode.cpp
    bytecode.cpp
    data.cpp
    pyc_code.cpp
    pyc_module.cpp
    pyc_numeric.cpp
    pyc_object.cpp
    pyc_sequence.cpp
    pyc_string.cpp
    bytes/python_1_0.cpp
    bytes/python_1_1.cpp
    bytes/python_1_3.cpp
    bytes/python_1_4.cpp
    bytes/python_1_5.cpp
    bytes/python_1_6.cpp
    bytes/python_2_0.cpp
    bytes/python_2_1.cpp
    bytes/python_2_2.cpp
    bytes/python_2_3.cpp
    bytes/python_2_4.cpp
    bytes/python_2_5.cpp
    bytes/python_2_6.cpp
    bytes/python_2_7.cpp
    bytes/python_3_0.cpp
    bytes/python_3_1.cpp
    bytes/python_3_2.cpp
    bytes/python_3_3.cpp
    bytes/python_3_4.cpp
    bytes/python_3_5.cpp
    bytes/python_3_6.cpp
    bytes/python_3_7.cpp
    bytes/python_3_8.cpp
    bytes/python_3_9.cpp
    bytes/python_3_10.cpp
    bytes/python_3_11.cpp
    bytes/python_3_12.cpp
    bytes/python_3_13.cpp
)

install(TARGETS pyarmor-1shot
    RUNTIME DESTINATION ${CMAKE_CURRENT_SOURCE_DIR}/helpers)
