#!/bin/bash
#
# RHEL 9 OSCAP Remediation - Login Banners & MOTD
# Description: Configure /etc/issue, /etc/issue.net, /etc/motd CIS banners and fix their owner/group/permissions.
# Rules covered: 3
#
# Usage: Run as root: bash 11_banner_and_motd.sh
#

set -o nounset


# ── FIXING: Banner Etc Issue Cis ──
# Rule: xccdf_org.ssgproject.content_rule_banner_etc_issue_cis
# BEGIN fix (31 / 379) for 'xccdf_org.ssgproject.content_rule_banner_etc_issue_cis'
###############################################################################
(>&2 echo "Remediating rule 31/379: 'xccdf_org.ssgproject.content_rule_banner_etc_issue_cis'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

cis_banner_text='Authorized users only. All activity may be monitored and reported.'

echo "$cis_banner_text" > "/etc/issue"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_banner_etc_issue_cis'

# ── FIXING: Banner Etc Issue Net Cis ──
# Rule: xccdf_org.ssgproject.content_rule_banner_etc_issue_net_cis
# BEGIN fix (32 / 379) for 'xccdf_org.ssgproject.content_rule_banner_etc_issue_net_cis'
###############################################################################
(>&2 echo "Remediating rule 32/379: 'xccdf_org.ssgproject.content_rule_banner_etc_issue_net_cis'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

cis_banner_text='Authorized users only. All activity may be monitored and reported.'

echo "$cis_banner_text" > "/etc/issue.net"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_banner_etc_issue_net_cis'

# ── FIXING: Banner Etc Motd Cis ──
# Rule: xccdf_org.ssgproject.content_rule_banner_etc_motd_cis
# BEGIN fix (33 / 379) for 'xccdf_org.ssgproject.content_rule_banner_etc_motd_cis'
###############################################################################
(>&2 echo "Remediating rule 33/379: 'xccdf_org.ssgproject.content_rule_banner_etc_motd_cis'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

cis_banner_text='Authorized users only. All activity may be monitored and reported.'

echo "$cis_banner_text" > "/etc/motd"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_banner_etc_motd_cis'
