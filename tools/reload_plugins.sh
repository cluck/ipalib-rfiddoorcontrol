#!/bin/bash

# This forces browsers out there to reload the plugins
#
# Related Bug:
# https://fedorahosted.org/freeipa/ticket/2679

num_version=$(grep 'num_version: ' /usr/share/ipa/ui/js/libs/loader.js | cut -d\' -f2)
stats=0
for plugin in /usr/share/ipa/ui/js/plugins/* ; do
    plugin_stats=$(stat -c %Y "$plugin"/$(basename "$plugin").js | cut -d ' ' -f1)
    if [ $plugin_stats -gt $stats ] ; then
        stats=$plugin_stats
    fi
done
sed -i "s,^.*num_version: .*$,        num_version: '${num_version%.*}.${stats}'\,," /usr/share/ipa/ui/js/libs/loader.js

