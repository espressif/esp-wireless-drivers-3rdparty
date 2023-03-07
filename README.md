# Espressif Wireless Framework

## Introduction

This project is used to integrate ESP32 family SoC's wireless software drivers into other platforms, like NuttX and Zephyr.

The wireless driver contains binary blobs as well as sources that need to be compiled on 3rd party platforms. Specifically, one would need the binary blobs, the wpa_supplicant and the Mbed TLS implementation from ESP-IDF.

## How to Use this Repository

This repository adds ESP-IDF as a submodule directly. Getting the header files, sources and binary libraries from ESP-IDF is part of the work. The target platform would need to provide the adapter functionalities and, possibly, apply patches to use the code.

### Getting the Headers, Sources and Libraries

The target platform would need:

1. Clone this repository and its submodules recursively;
2. From [ESP-IDF's esp_wifi component (esp-idf/components/esp_wifi)](esp-idf/components/esp_wifi)
    1. Include header files from [include](esp-idf/components/esp_wifi/include)
    2. Get binary libraries from [lib](esp-idf/components/esp_wifi/lib)
3. From [ESP-IDF's esp_phy component (esp-idf/components/esp_phy)](esp-idf/components/esp_phy)
    1. Include header files from [include](esp-idf/components/esp_phy/include)
    2. Include header files from [\<chip\>/include](esp-idf/components/esp_phy/esp32/include) (ESP32 used as an example)
    3. Get binary libraries from [lib](esp-idf/components/esp_phy/lib)
4. Include auxiliary header files:
    1. [esp-idf/components/esp_common/include](esp-idf/components/esp_common/include)
    2. [esp-idf/components/esp_event/include](esp-idf/components/esp_event/include)
    2. [esp-idf/components/nvs_flash/include](esp-idf/components/nvs_flash/include)
    2. [esp-idf/components/esp_system/include](esp-idf/components/esp_system/include)
    2. [esp-idf/components/esp_hw_support/include](esp-idf/components/esp_hw_support/include)
    2. [esp-idf/components/esp_timer/include](esp-idf/components/esp_timer/include)
    2. [esp-idf/components/esp_rom/include](esp-idf/components/esp_rom/include)
        1. [esp-idf/components/esp_rom/include/\<chip\>](esp-idf/components/esp_rom/include/esp32) (ESP32 used as an example)
    2. [esp-idf/components/soc/\<chip\>/include](esp-idf/components/soc/esp32/include) (ESP32 used as an example)
5. From ESP-IDF's Mbed TLS component:
    1. Include header files from:
        1. [esp-idf/components/mbedtls/mbedtls/include](esp-idf/components/mbedtls/mbedtls/include)
        2. [esp-idf/components/mbedtls/mbedtls/library](esp-idf/components/mbedtls/mbedtls/library)
        3. [esp-idf/components/mbedtls/port/include](esp-idf/components/mbedtls/port/include)
    2. Build sources from:
        1. [esp-idf/components/mbedtls/mbedtls/library](esp-idf/components/mbedtls/mbedtls/library)
        2. [esp-idf/components/mbedtls/port](esp-idf/components/mbedtls/port)
        3. [esp-idf/components/mbedtls/port/\<cipher_suites\>](esp-idf/components/mbedtls/port/md) (md used as an example. Build cipher suites sources when necessary)
6. From ESP-IDF's wpa_supplicant component:
    1. Include header files from:
        1. [esp-idf/components/wpa_supplicant/include](esp-idf/components/wpa_supplicant/include)
        2. [esp-idf/components/wpa_supplicant/src](esp-idf/components/wpa_supplicant/src)
        3. [esp-idf/components/wpa_supplicant/src/ap](esp-idf/components/wpa_supplicant/src/ap)
        4. [esp-idf/components/wpa_supplicant/src/common](esp-idf/components/wpa_supplicant/src/common)
        5. [esp-idf/components/wpa_supplicant/src/crypto](esp-idf/components/wpa_supplicant/src/crypto)
        6. [esp-idf/components/wpa_supplicant/src/utils](esp-idf/components/wpa_supplicant/src/utils)
        7. [esp-idf/components/wpa_supplicant/port/include](esp-idf/components/wpa_supplicant/port/include)
        8. [esp-idf/components/wpa_supplicant/esp_supplicant/include](esp-idf/components/wpa_supplicant/esp_supplicant/include)
        9. [esp-idf/components/wpa_supplicant/esp_supplicant/src](esp-idf/components/wpa_supplicant/esp_supplicant/src)
    2. Build sources from:
        1. [esp-idf/components/wpa_supplicant/src/ap](esp-idf/components/wpa_supplicant/src/ap)
        2. [esp-idf/components/wpa_supplicant/src/common](esp-idf/components/wpa_supplicant/src/common)
        3. [esp-idf/components/wpa_supplicant/src/crypto](esp-idf/components/wpa_supplicant/src/crypto)
        4. [esp-idf/components/wpa_supplicant/src/eap_peer](esp-idf/components/wpa_supplicant/src/eap_peer)
        5. [esp-idf/components/wpa_supplicant/src/rsn_supp](esp-idf/components/wpa_supplicant/src/rsn_supp)
        6. [esp-idf/components/wpa_supplicant/src/utils](esp-idf/components/wpa_supplicant/src/utils)
        7. [esp-idf/components/wpa_supplicant/port](esp-idf/components/wpa_supplicant/port)
        8. [esp-idf/components/wpa_supplicant/esp_supplicant/src](esp-idf/components/wpa_supplicant/esp_supplicant/src)
        9. [esp-idf/components/wpa_supplicant/esp_supplicant/src/crypto](esp-idf/components/wpa_supplicant/esp_supplicant/src/crypto)

> **Note**
> Not all mentioned sources are required to be built. It's feature-dependent. Please check which sources are built on NuttX in [nuttx/arch/xtensa/src/esp32s3/Make.defs](https://github.com/apache/nuttx/blob/master/arch/xtensa/src/esp32s3/Make.defs)

### Applying Platform-specific Patches and Header/Source Files

Additional header files, source files and utils are required for each platform.

#### NuttX's patches

Patches need to be applied to ESP-IDF-related sources to build the Wi-Fi driver on NuttX. Files from [nuttx/patches/esp-idf](nuttx/patches/esp-idf) are applied after cloning this repository. Please check [nuttx/arch/xtensa/src/esp32s3/Make.defs](https://github.com/apache/nuttx/blob/master/arch/xtensa/src/esp32s3/Make.defs) for an example.

#### NuttX's include

Additional header files are necessary to build the Wi-Fi driver on NuttX. Files from [nuttx/include/esp32s3](nuttx/include/esp32s3) are included. Please check [nuttx/arch/xtensa/src/esp32s3/Make.defs](https://github.com/apache/nuttx/blob/master/arch/xtensa/src/esp32s3/Make.defs) for an example.

## Workarounds

This section explains the workaround for using ESP-IDF's sources on 3rd party platforms.
### Mbed TLS Symbol Collisions

ESP32 SoC family makes use of the Mbed TLS to implement [wpa_supplicant crypto functions](esp-idf/components/wpa_supplicant/src/crypto). However, this same application may be present on 3rd party platforms. This is true for NuttX, for example.

In order to provide complete userspace/kernel separation and to avoid problems regarding the Mbed TLS version, the ESP32 implementation builds a custom version of Mbed TLS based on ESP-IDF's. However, there would be symbol collision if the Mbed TLS is used natively on the platform. To avoid this, functions and global variables with external linkage from the ESP32-custom Mbed TLS are then prefixed.

This is done through patches that apply the prefix. Please check [nuttx/patches/esp-idf/0001-mbetls_port_add_prefix.patch](nuttx/patches/esp-idf/0001-mbetls_port_add_prefix.patch), used in NuttX.

## Updating Sources

Updating the sources is as simple as checking out the ESP-IDF submodule (and its submodules recursively). However, it's needed to update the patches that are applied on the platforms.

### Re-adding the Prefix to Avoid Symbol Collision

#### Create ctags file

This file maps all the functions and global variables used by the Mbed TLS library. To generate it:

> **Warning**
> This requires the [`ctags`](https://github.com/universal-ctags/ctags) tool needs to be installed on the system.

Once installed, regenerate :

```
ctags -f utils/ctags/mbedtls/tags --kinds-c=fv esp-idf/components/mbedtls/mbedtls/library/*.c
```

> **Note**
> This file only needs to be updated when ESP-IDF's Mbed TLS submodule is updated. This file is versioned in [utils/ctags/mbedtls/tags](utils/ctags/mbedtls/tags)

#### Generate Prefix Patch for Mbed TLS

Use [prefixer](utils/prefixer.sh) script to add the `esp_` prefix to Mbed TLS-related functions and variables.

```
cd utils/
git -C ../esp-idf reset --hard
git -C ../esp-idf/components/mbedtls/mbedtls reset --hard
./prefixer.sh ctags/mbedtls/tags ../esp-idf/components/mbedtls/mbedtls
mkdir -p ../nuttx/patches/esp-idf/submodules/
git -C ../esp-idf/components/mbedtls/mbedtls diff --full-index --binary > ../nuttx/patches/esp-idf/submodules/0001-mbedtls_add_prefix.patch
git -C ../esp-idf/components/mbedtls/mbedtls reset --hard
```

#### Generate Prefix Patch for ESP-IDF's Mbed TLS port

```
git -C ../esp-idf reset --hard
./prefixer.sh ctags/mbedtls/tags ../esp-idf/components/mbedtls/port
git -C ../esp-idf diff --full-index --binary > ../nuttx/patches/esp-idf/0001-mbedtls_port_add_prefix.patch
```

#### Generate Prefix Patch for wpa_supplicant

```
git -C ../esp-idf reset --hard
./prefixer.sh ctags/mbedtls/tags ../esp-idf/components/wpa_supplicant
git -C ../esp-idf/ diff --full-index --binary > ../nuttx/patches/esp-idf/0002-wpa_supplicant_add_prefix.patch
```

### Check Other Patches

Other patches other than those that add Mbed TLS-related prefixes are provided. Please check them after updating the sources.

NuttX patches are stored on [nuttx/patches](nuttx/patches).
