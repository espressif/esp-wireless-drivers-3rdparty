# Espressif Wireless Framework

## Introduction

This project is used to integrate ESP32 family SoC's wireless software drivers into other platforms, like NuttX.

Wireless software drivers mainly contains of hardware drivers, wireless protocols and utils.

## Update Software of Wireless Framework

1. setup compiling environment by `. ./export.sh` in esp-idf directory

2. in the root directory of this project, input command `make` to recompile `helper_project` to generate new libraries and header files

3. file of `version` in the root directory mark the esp-idf's version
