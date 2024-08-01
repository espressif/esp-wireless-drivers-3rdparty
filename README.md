# `ESP-HAL-3RDPARTY`

This branch is a release version intended to be used by NuttX as a HAL *(Hardware Abstraction Layer*), including Wi-Fi features.

## Release v5.1.c

This release was based on the top of [`sync/release_v5.1.c`](../../../tree/sync/release_v5.1.c)., forked on 2023-08-14 ([`22d299b3d6436b4442ffd06bb575467e3fd5f56d`](../../../tree/22d299b3d6436b4442ffd06bb575467e3fd5f56d)), creating the branch [`release/v5.1.c`](../../../tree/release/v5.1.c).

## How to Use this Release

This branch is intended to be downloaded/cloned by NuttX's build system, using the provided source to build Espressif's SoCs on NuttX.

### Organization
This branch is organized into the following directories:

#### `components`
The [`components`](./components/) folder contains the components sourced from [`sync/release_v5.1.c`](../../../tree/sync/release_v5.1.c) and the additions made to enable building the sources on NuttX. Please note that these components may contain git submodules.

> **Note**
> Not all sources under `components` are required to build NuttX: it's feature-dependent. Please check which sources are built on NuttX when build, for instance, ESP32-S3's Wi-Fi: [nuttx/arch/xtensa/src/esp32s3/Wireless.mk](https://github.com/apache/nuttx/blob/master/arch/xtensa/src/esp32s3/Wireless.mk).

> **Note**
> Please note that, preferably, modifications on source should be made using the preprocessor macro `__NuttX__`.

#### `nuttx`

The [`nuttx`](./nuttx) directory contains the following sub-directories:

##### `nuttx/include`

Includes headers that are used specifically to build NuttX that are not available in `components` (or that can't be directly added there), including API translations, macro (re)-definitions, and other necessary files that are meant to interface with sources and header files in `components`.

##### `nuttx/<chip>/include`

Similar to `nuttx/include`, but intended to be used specifically by a particular chip.

##### `nuttx/patches`

Provide patches to be applied in the source code when it isn't suitable to directly change it. Specifically, patches are used to change the source code of git submodules. The Mbed TLS is a submodule in [`components/mbedtls/mbedtls`](./components/mbedtls/mbedtls) folder and directly changing its source would require keeping a separate remote for the Mbed TLS. Instead, we can provide patches to be applied before building the Mbed TLS.

> **Note**
> The path under `nuttx/patches` is related to the path where the patch is meant to be applied: [`nuttx/patches/components/mbedtls/mbedtls/0001-mbedtls_add_prefix.patch`](nuttx/patches/components/mbedtls/mbedtls/0001-mbedtls_add_prefix.patch), for instance, is meant to be applied at [`components/mbedtls/mbedtls/`](components/mbedtls/mbedtls/)

### Workarounds

This section explains in-depth the workarounds for using the components on NuttX.
#### Mbed TLS Symbol Collisions

ESP32 SoC family makes use of the Mbed TLS to implement [wpa_supplicant crypto functions](components/wpa_supplicant/src/crypto). However, this same application may be present on 3rd party platforms. This is true for NuttX, for example. Thus, to provide complete userspace/kernel separation and to avoid problems regarding the Mbed TLS version, the ESP32 implementation builds a custom version of Mbed TLS. To avoid symbol collision if NuttX's Mbed TLS is used, functions and global variables with external linkage from the ESP32-custom Mbed TLS are then prefixed.

This is done through patches that apply the prefix. Please check [nuttx/patches/components/mbedtls/mbedtls](nuttx/patches/components/mbedtls/mbedtls) for checking the patches that are meant to be applied on Mbed TLS submodule that is used by the Wi-Fi driver.
