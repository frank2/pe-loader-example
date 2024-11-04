cmake_minimum_required(VERSION 3.15)

project(loader C)

add_executable(loader main.c)
add_subdirectory(dll)
add_subdirectory(exe)
add_dependencies(loader dll exe)

enable_testing()
add_test(NAME test_dll COMMAND "$<TARGET_FILE:loader>" "$<TARGET_FILE:dll>")
add_test(NAME test_exe COMMAND "$<TARGET_FILE:loader>" "$<TARGET_FILE:exe>")
