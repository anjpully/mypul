#!/bin/bash
#
# RHEL 9 OSCAP Remediation - SELinux Configuration
# Description: SELinux enforcing state, targeted policy, libselinux installation, mcstrans removal, GRUB SELinux boot parameter.
# Rules covered: 3
#
# Usage: Run as root: bash 09_selinux.sh
#

set -o nounset


# ── FIXING: Selinux Not Disabled ──
# Rule: xccdf_org.ssgproject.content_rule_selinux_not_disabled
# BEGIN fix (216 / 379) for 'xccdf_org.ssgproject.content_rule_selinux_not_disabled'
###############################################################################
(>&2 echo "Remediating rule 216/379: 'xccdf_org.ssgproject.content_rule_selinux_not_disabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if [ -e "/etc/selinux/config" ] ; then
    
    LC_ALL=C sed -i "/^SELINUX=/Id" "/etc/selinux/config"
else
    touch "/etc/selinux/config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/selinux/config"

cp "/etc/selinux/config" "/etc/selinux/config.bak"
# Insert at the end of the file
printf '%s\n' "SELINUX=permissive" >> "/etc/selinux/config"
# Clean up after ourselves.
rm "/etc/selinux/config.bak"

fixfiles onboot
fixfiles -f relabel

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_selinux_not_disabled'

# ── FIXING: Selinux Policytype ──
# Rule: xccdf_org.ssgproject.content_rule_selinux_policytype
# BEGIN fix (217 / 379) for 'xccdf_org.ssgproject.content_rule_selinux_policytype'
###############################################################################
(>&2 echo "Remediating rule 217/379: 'xccdf_org.ssgproject.content_rule_selinux_policytype'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

var_selinux_policy_name='targeted'


if [ -e "/etc/selinux/config" ] ; then
    
    LC_ALL=C sed -i "/^SELINUXTYPE=/Id" "/etc/selinux/config"
else
    touch "/etc/selinux/config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/selinux/config"

cp "/etc/selinux/config" "/etc/selinux/config.bak"
# Insert at the end of the file
printf '%s\n' "SELINUXTYPE=$var_selinux_policy_name" >> "/etc/selinux/config"
# Clean up after ourselves.
rm "/etc/selinux/config.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_selinux_policytype'

# ── FIXING: Selinux State ──
# Rule: xccdf_org.ssgproject.content_rule_selinux_state
# BEGIN fix (218 / 379) for 'xccdf_org.ssgproject.content_rule_selinux_state'
###############################################################################
(>&2 echo "Remediating rule 218/379: 'xccdf_org.ssgproject.content_rule_selinux_state'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

var_selinux_state='enforcing'


if [ -e "/etc/selinux/config" ] ; then
    
    LC_ALL=C sed -i "/^SELINUX=/Id" "/etc/selinux/config"
else
    touch "/etc/selinux/config"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/selinux/config"

cp "/etc/selinux/config" "/etc/selinux/config.bak"
# Insert at the end of the file
printf '%s\n' "SELINUX=$var_selinux_state" >> "/etc/selinux/config"
# Clean up after ourselves.
rm "/etc/selinux/config.bak"

fixfiles onboot
fixfiles -f relabel

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_selinux_state'
