@echo off
cd llama.cpp
cmake -G "MinGW Makefiles" -B build
cmake --build build --config Release
