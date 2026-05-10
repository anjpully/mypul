#!/bin/bash
#
# RHEL 9 OSCAP Remediation - AIDE File Integrity Monitoring
# Description: Install AIDE, build the initial database, verify audit tool integrity, configure periodic AIDE cron checks.
# Rules covered: 3
#
# Usage: Run as root: bash 12_aide_integrity.sh
#

set -o nounset


# ── FIXING: Aide Build Database ──
# Rule: xccdf_org.ssgproject.content_rule_aide_build_database
# BEGIN fix (2 / 379) for 'xccdf_org.ssgproject.content_rule_aide_build_database'
###############################################################################
(>&2 echo "Remediating rule 2/379: 'xccdf_org.ssgproject.content_rule_aide_build_database'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if ! rpm -q --quiet "aide" ; then
    dnf install -y "aide"
fi

/usr/sbin/aide --init
/bin/cp -p /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_aide_build_database'

# ── FIXING: Aide Check Audit Tools ──
# Rule: xccdf_org.ssgproject.content_rule_aide_check_audit_tools
# BEGIN fix (3 / 379) for 'xccdf_org.ssgproject.content_rule_aide_check_audit_tools'
###############################################################################
(>&2 echo "Remediating rule 3/379: 'xccdf_org.ssgproject.content_rule_aide_check_audit_tools'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if ! rpm -q --quiet "aide" ; then
    dnf install -y "aide"
fi










if grep -i '^.*/usr/sbin/auditctl.*$' /etc/aide.conf; then
sed -i "s#.*/usr/sbin/auditctl.*#/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
else
echo "/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
fi

if grep -i '^.*/usr/sbin/auditd.*$' /etc/aide.conf; then
sed -i "s#.*/usr/sbin/auditd.*#/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
else
echo "/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
fi

if grep -i '^.*/usr/sbin/ausearch.*$' /etc/aide.conf; then
sed -i "s#.*/usr/sbin/ausearch.*#/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
else
echo "/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
fi

if grep -i '^.*/usr/sbin/aureport.*$' /etc/aide.conf; then
sed -i "s#.*/usr/sbin/aureport.*#/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
else
echo "/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
fi

if grep -i '^.*/usr/sbin/autrace.*$' /etc/aide.conf; then
sed -i "s#.*/usr/sbin/autrace.*#/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
else
echo "/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
fi

if grep -i '^.*/usr/sbin/augenrules.*$' /etc/aide.conf; then
sed -i "s#.*/usr/sbin/augenrules.*#/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
else
echo "/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
fi

if grep -i '^.*/usr/sbin/rsyslogd.*$' /etc/aide.conf; then
sed -i "s#.*/usr/sbin/rsyslogd.*#/usr/sbin/rsyslogd p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide.conf
else
echo "/usr/sbin/rsyslogd p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_aide_check_audit_tools'

# ── FIXING: Aide Periodic Cron Checking ──
# Rule: xccdf_org.ssgproject.content_rule_aide_periodic_cron_checking
# BEGIN fix (4 / 379) for 'xccdf_org.ssgproject.content_rule_aide_periodic_cron_checking'
###############################################################################
(>&2 echo "Remediating rule 4/379: 'xccdf_org.ssgproject.content_rule_aide_periodic_cron_checking'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if ! rpm -q --quiet "aide" ; then
    dnf install -y "aide"
fi

if ! grep -q "/usr/sbin/aide --check" /etc/crontab ; then
    echo "05 4 * * * root /usr/sbin/aide --check" >> /etc/crontab
else
    sed -i '\!^.* --check.*$!d' /etc/crontab
    echo "05 4 * * * root /usr/sbin/aide --check" >> /etc/crontab
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_aide_periodic_cron_checking'
