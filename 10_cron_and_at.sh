#!/bin/bash
#
# RHEL 9 OSCAP Remediation - Cron & At Job Scheduling Hardening
# Description: cron and at file permissions, group/owner hardening, allow/deny file management, crond service enabling.
# Rules covered: 3
#
# Usage: Run as root: bash 10_cron_and_at.sh
#

set -o nounset


# ── FIXING: File At Deny Not Exist ──
# Rule: xccdf_org.ssgproject.content_rule_file_at_deny_not_exist
# BEGIN fix (240 / 379) for 'xccdf_org.ssgproject.content_rule_file_at_deny_not_exist'
###############################################################################
(>&2 echo "Remediating rule 240/379: 'xccdf_org.ssgproject.content_rule_file_at_deny_not_exist'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if [[ -f  /etc/at.deny ]]; then
        rm /etc/at.deny
    fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_at_deny_not_exist'

# ── FIXING: File Cron Allow Exists ──
# Rule: xccdf_org.ssgproject.content_rule_file_cron_allow_exists
# BEGIN fix (241 / 379) for 'xccdf_org.ssgproject.content_rule_file_cron_allow_exists'
###############################################################################
(>&2 echo "Remediating rule 241/379: 'xccdf_org.ssgproject.content_rule_file_cron_allow_exists'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

touch /etc/cron.allow
    chown 0 /etc/cron.allow
    chmod 0600 /etc/cron.allow

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_cron_allow_exists'

# ── FIXING: File Cron Deny Not Exist ──
# Rule: xccdf_org.ssgproject.content_rule_file_cron_deny_not_exist
# BEGIN fix (242 / 379) for 'xccdf_org.ssgproject.content_rule_file_cron_deny_not_exist'
###############################################################################
(>&2 echo "Remediating rule 242/379: 'xccdf_org.ssgproject.content_rule_file_cron_deny_not_exist'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if [[ -f  /etc/cron.deny ]]; then
        rm /etc/cron.deny
    fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_cron_deny_not_exist'
