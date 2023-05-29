# esp-wireless-drivers-3rdparty

Wireless components for Espressif chips.

Currently, the branches are all synchronized from IDF by scripts under given rules.

Except for the scripts, no manual development will happen here.

## Branch naming convention

sync-[name]-[branch]

Where:

- `sync` means this is a branch maintained by the script. Will not be able to be merged with each other.
- `[name]`: either a number (whose file list will be described somewhere), or a single component (in case someone needs it...)
- `[branch]`: the IDF branch to sync from, e.g. `master`, `release/v5.0`

## Existing branches

- [`sync-1-release_v5.0`](../../tree/sync-1-release_v5.0):
    - Based on IDF `release/v5.0` branch.
    - Includes components: `esp_event`, `esp_phy`, `esp_wifi`, `mbedtls`, `wpa_supplicant`.
- [`sync-2-release_v5.0`](../../tree/sync-2-release_v5.0):
    - Based on IDF `release/v5.0` branch.
    - Includes components: `esp_common`, `esp_event`,`esp_hw_support`, `esp_phy`, `esp_rom`, `esp_system`,`esp_timer`, `esp_wifi`, `mbedtls`, `soc`, `wpa_supplicant`

## Restrictions

1. Sync branches don't have common ancestors

   This may cause some problems when you merge or pick from these branches

2. Can't easily modify the file list of an existing branch

   The tool used by the sync script converts commits of IDF into new ones on the given branch. The history is kept while the files are filtered according to the given file list.

   The generated commits will have the same SHA as long as the commit author, date, message and change list are the same.

   Any modification to the script's strategy of a sync branch (including modifying the file list) will change the SHA of the commits, forbidding the generated branch being merged (pushed) to the existing one.

   When we need to modify the file list or any other part of the commit, it's suggested to create a new branch.
