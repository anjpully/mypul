#!/bin/bash
#
# RHEL 9 OSCAP Remediation - Logging & Journald Configuration
# Description: rsyslog file permissions/ownership, journald compression and storage, systemd-journald service enablement.
# Rules covered: 2
#
# Usage: Run as root: bash 13_logging_and_journald.sh
#

set -o nounset


# ── FIXING: Journald Compress ──
# Rule: xccdf_org.ssgproject.content_rule_journald_compress
# BEGIN fix (112 / 379) for 'xccdf_org.ssgproject.content_rule_journald_compress'
###############################################################################
(>&2 echo "Remediating rule 112/379: 'xccdf_org.ssgproject.content_rule_journald_compress'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

found=false

# set value in all files if they contain section or key
for f in $(echo -n "/etc/systemd/journald.conf.d/complianceascode_hardening.conf /etc/systemd/journald.conf.d/*.conf /etc/systemd/journald.conf"); do
    if [ ! -e "$f" ]; then
        continue
    fi

    # find key in section and change value
    if grep -qzosP "[[:space:]]*\[Journal\]([^\n\[]*\n+)+?[[:space:]]*Compress" "$f"; then

            sed -i "s/Compress[^(\n)]*/Compress=yes/" "$f"

            found=true

    # find section and add key = value to it
    elif grep -qs "[[:space:]]*\[Journal\]" "$f"; then

            sed -i "/[[:space:]]*\[Journal\]/a Compress=yes" "$f"

            found=true
    fi
done

# if section not in any file, append section with key = value to FIRST file in files parameter
if ! $found ; then
    file=$(echo "/etc/systemd/journald.conf.d/complianceascode_hardening.conf /etc/systemd/journald.conf.d/*.conf /etc/systemd/journald.conf" | cut -f1 -d ' ')
    mkdir -p "$(dirname "$file")"

    echo -e "[Journal]\nCompress=yes" >> "$file"

fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_journald_compress'

# ── FIXING: Journald Storage ──
# Rule: xccdf_org.ssgproject.content_rule_journald_storage
# BEGIN fix (113 / 379) for 'xccdf_org.ssgproject.content_rule_journald_storage'
###############################################################################
(>&2 echo "Remediating rule 113/379: 'xccdf_org.ssgproject.content_rule_journald_storage'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

found=false

# set value in all files if they contain section or key
for f in $(echo -n "/etc/systemd/journald.conf.d/complianceascode_hardening.conf /etc/systemd/journald.conf.d/*.conf /etc/systemd/journald.conf"); do
    if [ ! -e "$f" ]; then
        continue
    fi

    # find key in section and change value
    if grep -qzosP "[[:space:]]*\[Journal\]([^\n\[]*\n+)+?[[:space:]]*Storage" "$f"; then

            sed -i "s/Storage[^(\n)]*/Storage=persistent/" "$f"

            found=true

    # find section and add key = value to it
    elif grep -qs "[[:space:]]*\[Journal\]" "$f"; then

            sed -i "/[[:space:]]*\[Journal\]/a Storage=persistent" "$f"

            found=true
    fi
done

# if section not in any file, append section with key = value to FIRST file in files parameter
if ! $found ; then
    file=$(echo "/etc/systemd/journald.conf.d/complianceascode_hardening.conf /etc/systemd/journald.conf.d/*.conf /etc/systemd/journald.conf" | cut -f1 -d ' ')
    mkdir -p "$(dirname "$file")"

    echo -e "[Journal]\nStorage=persistent" >> "$file"

fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_journald_storage'
