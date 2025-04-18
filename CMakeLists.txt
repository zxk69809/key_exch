# 设置 CMake 最低版本要求
cmake_minimum_required(VERSION 3.10)

# 设置项目名称
project(SM2KeyExchange)

# 设置 C 标准
set(CMAKE_C_STANDARD 99)

# 添加 GmSSL 子模块
add_subdirectory(GmSSL)

# 添加可执行文件
add_executable(sm2_exchange_test main.c softexch.c)

# 链接 GmSSL 库
target_link_libraries(sm2_exchange_test gmssl)

# 包含 GmSSL 头文件目录
target_include_directories(sm2_exchange_test PRIVATE GmSSL/include)    