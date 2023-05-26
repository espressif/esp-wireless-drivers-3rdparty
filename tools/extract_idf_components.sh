#!/bin/bash

set -eux

# ESP_WIRELESS_URL
# IDF_URL

# Usage: clone_idf ESP_IDF_BRANCH
clone_idf() {
    rm -rf download_idf
    git clone --single-branch --branch "$1" "${IDF_URL}" download_idf
}

# Usage: find_pattern STRING
find_pattern() {
    git --no-pager log -i --grep "$1" > issue_found.txt
    if [[ $(cat issue_found.txt | wc -l) > 0 ]]; then
        ISSUE_NUM=$(grep "^commit " issue_found.txt | wc -l)
        die "${ISSUE_NUM} $1 found. See issue_found.txt"
    fi
}

check_links() {
    find_pattern 'github.com/[^ /]*/[^ /]*/\(issues\|pull\)'
    find_pattern 'espressif/esp-idf[!#$&~%^]'
}

# Usage: extract_components ESP_IDF_BRANCH SYNC_BRANCH_NAME ARGS...
extract_components() {
    ESP_IDF_BRANCH=$1
    SYNC_BRANCH_NAME=$2
    ARGS="${@:3}"

    echo "Cloning ESP-IDF (${ESP_IDF_BRANCH})"

    clone_idf "${ESP_IDF_BRANCH}"

    echo "Extract to branch ${SYNC_BRANCH_NAME} with arg list: '$ARGS'"

    FOLDER_NAME="esp-idf-${SYNC_BRANCH_NAME}"

    rm -rf ${FOLDER_NAME}
    cp -r download_idf ${FOLDER_NAME}

    pushd ${FOLDER_NAME}
    git filter-repo "${@:3}"

    check_links

    git checkout -B ${SYNC_BRANCH_NAME}
    git push ${ESP_WIRELESS_URL} ${SYNC_BRANCH_NAME}
    git clean -xdff
    popd
}

# Usage get_arg_by_components [COMPONENTS...]
get_arg_by_components() {
    RET=""
    for COMPONENT in $*
    do
        # There will be an redundant trailing space
        RET+="--path components/${COMPONENT} "
    done
    echo ${RET}
}

LIC_ARG="--path LICENSE"

# The commits have the same SHA as long as the commit author, date, message and change list are the same.
# Any modification to the strategy will create new branch that cannot be merged (pushed) to the existing one.

MSG_CALLBACK="
        # (https)?github.com/[user]/[proj]/*/[id] -> [Github: [user]/proj]/*/[id]
        msg1 = re.sub(br'(?:(?:https?://)?github\.com/)([^\s/]+/[^\s/]+)/([^/]+/[0-9]+)', br'[Github: \1]/\2', message)

        # espressif/esp-idf -> [ESP_IDF] (except from [Github: espressif/esp-idf])
        return re.sub(br'espressif/esp-idf([^\]])', br'[ESP_IDF]\1', msg1)
    "
ARG="${LIC_ARG} $(get_arg_by_components esp_event esp_phy esp_wifi mbedtls wpa_supplicant)"
extract_components "release/v5.0" "sync-1-release_v5.0" ${ARG} --message-callback "${MSG_CALLBACK}"

# Add new one here if you have new requirement

# Push to protected branch will cause that branch to appear on Github.
# Try with non-protected branch first.
# ARG="${LIC_ARG} $(get_arg_by_components esp_event esp_phy esp_wifi mbedtls wpa_supplicant)"
# extract_components "release/v5.0" "test-sync-1-release_v5.0" ${ARG} --message-callback "${MSG_CALLBACK}"

############## Deprecated Syncs ###################
