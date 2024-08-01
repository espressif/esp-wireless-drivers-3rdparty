#!/usr/bin/env bash

usage() {
	echo "Usage: $0 ctags_file folder_to_find_and_replace"
    exit 1
}

ctags_file="$1"; shift
destination="$1"

if [ -z "$ctags_file" ] || [ -z "$destination" ]; then
    usage
fi

prefix="esp_"
substitutions=0

readtags_cmd="readtags -t ${ctags_file} -F '(list \$name #t)' -l"
echo "readtags command is: ${readtags_cmd}"

while read -r mbedtls_function ; do
    find_cmd="grep -rl \"--include=*.[ch]\" '\b${mbedtls_function}\b' ${destination}"
    echo "Find command is: ${find_cmd}"
    find_results="$(eval ${find_cmd})"

    if [ -n "${find_results}" ]; then
        find_results_n="$(echo "${find_results}" | wc -l)"
        replace_cmd="echo \""${find_results}"\" | xargs sed -i \"s/\<${mbedtls_function}\>/${prefix}${mbedtls_function}/g\""
        echo "Replace command is: ${replace_cmd}"
        eval "${replace_cmd}"
        replace_results=$?
        substitutions=$((substitutions + find_results_n))
        
        if [ "${replace_results}" -ne '0' ]; then
            echo "Failed to add \"${prefix}\" to \"${mbedtls_function}\""
            echo "Aborting..."
            exit 1
        fi
        echo "Added \"${prefix}\" prefix to \"${mbedtls_function}\" on the following occurences:"
        echo "${find_results}"
    fi

done < <(eval "${readtags_cmd}" )

echo "The prefix \"${prefix}\" was added to ${substitutions} functions"
