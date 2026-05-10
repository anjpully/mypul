#!/bin/bash
#
# RHEL 9 OSCAP Remediation - Filesystem Partitions & Mount Options
# Description: Separate partition checks, and mount options (nodev/noexec/nosuid) for /home, /tmp, /var, /var/log, /dev/shm, etc.
# Rules covered: 27
#
# Usage: Run as root: bash 03_filesystem_and_mount_options.sh
#

set -o nounset


# ── FIXING: Partition For Dev Shm ──
# Rule: xccdf_org.ssgproject.content_rule_partition_for_dev_shm
# BEGIN fix (7 / 379) for 'xccdf_org.ssgproject.content_rule_partition_for_dev_shm'
###############################################################################
(>&2 echo "Remediating rule 7/379: 'xccdf_org.ssgproject.content_rule_partition_for_dev_shm'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_partition_for_dev_shm' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_partition_for_dev_shm'

# ── FIXING: Partition For Home ──
# Rule: xccdf_org.ssgproject.content_rule_partition_for_home
# BEGIN fix (8 / 379) for 'xccdf_org.ssgproject.content_rule_partition_for_home'
###############################################################################
(>&2 echo "Remediating rule 8/379: 'xccdf_org.ssgproject.content_rule_partition_for_home'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_partition_for_home' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_partition_for_home'

# ── FIXING: Partition For Tmp ──
# Rule: xccdf_org.ssgproject.content_rule_partition_for_tmp
# BEGIN fix (9 / 379) for 'xccdf_org.ssgproject.content_rule_partition_for_tmp'
###############################################################################
(>&2 echo "Remediating rule 9/379: 'xccdf_org.ssgproject.content_rule_partition_for_tmp'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_partition_for_tmp' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_partition_for_tmp'

# ── FIXING: Partition For Var ──
# Rule: xccdf_org.ssgproject.content_rule_partition_for_var
# BEGIN fix (10 / 379) for 'xccdf_org.ssgproject.content_rule_partition_for_var'
###############################################################################
(>&2 echo "Remediating rule 10/379: 'xccdf_org.ssgproject.content_rule_partition_for_var'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_partition_for_var' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_partition_for_var'

# ── FIXING: Partition For Var Log ──
# Rule: xccdf_org.ssgproject.content_rule_partition_for_var_log
# BEGIN fix (11 / 379) for 'xccdf_org.ssgproject.content_rule_partition_for_var_log'
###############################################################################
(>&2 echo "Remediating rule 11/379: 'xccdf_org.ssgproject.content_rule_partition_for_var_log'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_partition_for_var_log' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_partition_for_var_log'

# ── FIXING: Partition For Var Log Audit ──
# Rule: xccdf_org.ssgproject.content_rule_partition_for_var_log_audit
# BEGIN fix (12 / 379) for 'xccdf_org.ssgproject.content_rule_partition_for_var_log_audit'
###############################################################################
(>&2 echo "Remediating rule 12/379: 'xccdf_org.ssgproject.content_rule_partition_for_var_log_audit'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_partition_for_var_log_audit' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_partition_for_var_log_audit'

# ── FIXING: Partition For Var Tmp ──
# Rule: xccdf_org.ssgproject.content_rule_partition_for_var_tmp
# BEGIN fix (13 / 379) for 'xccdf_org.ssgproject.content_rule_partition_for_var_tmp'
###############################################################################
(>&2 echo "Remediating rule 13/379: 'xccdf_org.ssgproject.content_rule_partition_for_var_tmp'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_partition_for_var_tmp' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_partition_for_var_tmp'

# ── FIXING: Dir Perms World Writable Sticky Bits ──
# Rule: xccdf_org.ssgproject.content_rule_dir_perms_world_writable_sticky_bits
# BEGIN fix (149 / 379) for 'xccdf_org.ssgproject.content_rule_dir_perms_world_writable_sticky_bits'
###############################################################################
(>&2 echo "Remediating rule 149/379: 'xccdf_org.ssgproject.content_rule_dir_perms_world_writable_sticky_bits'"); (
df --local -P | awk '{if (NR!=1) print $6}' \
| xargs -I '$6' find '$6' -xdev -type d \
\( -perm -0002 -a ! -perm -1000 \) 2>/dev/null \
-exec chmod a+t {} +

) # END fix for 'xccdf_org.ssgproject.content_rule_dir_perms_world_writable_sticky_bits'

# ── FIXING: Mount Option Dev Shm Nodev ──
# Rule: xccdf_org.ssgproject.content_rule_mount_option_dev_shm_nodev
# BEGIN fix (190 / 379) for 'xccdf_org.ssgproject.content_rule_mount_option_dev_shm_nodev'
###############################################################################
(>&2 echo "Remediating rule 190/379: 'xccdf_org.ssgproject.content_rule_mount_option_dev_shm_nodev'"); (
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ); then

function perform_remediation {
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /dev/shm)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nodev)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        # In iso9660 filesystems mtab could describe a "blocksize" value, this should be reflected in
        # fstab as "block".  The next variable is to satisfy shellcheck SC2050.
        fs_type="tmpfs"
        if [  "$fs_type" == "iso9660" ] ; then
            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< "$previous_mount_opts")
        fi
        echo "tmpfs /dev/shm tmpfs defaults,${previous_mount_opts}nodev 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep -q "nodev"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nodev|" /etc/fstab
    fi


    if mkdir -p "/dev/shm"; then
        if mountpoint -q "/dev/shm"; then
            mount -o remount --target "/dev/shm"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_mount_option_dev_shm_nodev'

# ── FIXING: Mount Option Dev Shm Noexec ──
# Rule: xccdf_org.ssgproject.content_rule_mount_option_dev_shm_noexec
# BEGIN fix (191 / 379) for 'xccdf_org.ssgproject.content_rule_mount_option_dev_shm_noexec'
###############################################################################
(>&2 echo "Remediating rule 191/379: 'xccdf_org.ssgproject.content_rule_mount_option_dev_shm_noexec'"); (
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ); then

function perform_remediation {
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /dev/shm)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|noexec)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        # In iso9660 filesystems mtab could describe a "blocksize" value, this should be reflected in
        # fstab as "block".  The next variable is to satisfy shellcheck SC2050.
        fs_type="tmpfs"
        if [  "$fs_type" == "iso9660" ] ; then
            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< "$previous_mount_opts")
        fi
        echo "tmpfs /dev/shm tmpfs defaults,${previous_mount_opts}noexec 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep -q "noexec"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,noexec|" /etc/fstab
    fi


    if mkdir -p "/dev/shm"; then
        if mountpoint -q "/dev/shm"; then
            mount -o remount --target "/dev/shm"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_mount_option_dev_shm_noexec'

# ── FIXING: Mount Option Dev Shm Nosuid ──
# Rule: xccdf_org.ssgproject.content_rule_mount_option_dev_shm_nosuid
# BEGIN fix (192 / 379) for 'xccdf_org.ssgproject.content_rule_mount_option_dev_shm_nosuid'
###############################################################################
(>&2 echo "Remediating rule 192/379: 'xccdf_org.ssgproject.content_rule_mount_option_dev_shm_nosuid'"); (
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ); then

function perform_remediation {
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /dev/shm)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nosuid)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        # In iso9660 filesystems mtab could describe a "blocksize" value, this should be reflected in
        # fstab as "block".  The next variable is to satisfy shellcheck SC2050.
        fs_type="tmpfs"
        if [  "$fs_type" == "iso9660" ] ; then
            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< "$previous_mount_opts")
        fi
        echo "tmpfs /dev/shm tmpfs defaults,${previous_mount_opts}nosuid 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep -q "nosuid"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nosuid|" /etc/fstab
    fi


    if mkdir -p "/dev/shm"; then
        if mountpoint -q "/dev/shm"; then
            mount -o remount --target "/dev/shm"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_mount_option_dev_shm_nosuid'

# ── FIXING: Mount Option Home Nodev ──
# Rule: xccdf_org.ssgproject.content_rule_mount_option_home_nodev
# BEGIN fix (193 / 379) for 'xccdf_org.ssgproject.content_rule_mount_option_home_nodev'
###############################################################################
(>&2 echo "Remediating rule 193/379: 'xccdf_org.ssgproject.content_rule_mount_option_home_nodev'"); (
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ) && { findmnt --kernel "/home" > /dev/null || findmnt --fstab "/home" > /dev/null; }; then

function perform_remediation {
    
        # the mount point /home has to be defined in /etc/fstab
        # before this remediation can be executed. In case it is not defined, the
        # remediation aborts and no changes regarding the mount point are done.
        mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" "/home")"

    grep "$mount_point_match_regexp" -q /etc/fstab \
        || { echo "The mount point '/home' is not even in /etc/fstab, so we can't set up mount options" >&2;
                echo "Not remediating, because there is no record of /home in /etc/fstab" >&2; return 1; }
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /home)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nodev)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        # In iso9660 filesystems mtab could describe a "blocksize" value, this should be reflected in
        # fstab as "block".  The next variable is to satisfy shellcheck SC2050.
        fs_type=""
        if [  "$fs_type" == "iso9660" ] ; then
            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< "$previous_mount_opts")
        fi
        echo " /home  defaults,${previous_mount_opts}nodev 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep -q "nodev"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nodev|" /etc/fstab
    fi


    if mkdir -p "/home"; then
        if mountpoint -q "/home"; then
            mount -o remount --target "/home"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_mount_option_home_nodev'

# ── FIXING: Mount Option Home Nosuid ──
# Rule: xccdf_org.ssgproject.content_rule_mount_option_home_nosuid
# BEGIN fix (194 / 379) for 'xccdf_org.ssgproject.content_rule_mount_option_home_nosuid'
###############################################################################
(>&2 echo "Remediating rule 194/379: 'xccdf_org.ssgproject.content_rule_mount_option_home_nosuid'"); (
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ) && { findmnt --kernel "/home" > /dev/null || findmnt --fstab "/home" > /dev/null; }; then

function perform_remediation {
    
        # the mount point /home has to be defined in /etc/fstab
        # before this remediation can be executed. In case it is not defined, the
        # remediation aborts and no changes regarding the mount point are done.
        mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" "/home")"

    grep "$mount_point_match_regexp" -q /etc/fstab \
        || { echo "The mount point '/home' is not even in /etc/fstab, so we can't set up mount options" >&2;
                echo "Not remediating, because there is no record of /home in /etc/fstab" >&2; return 1; }
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /home)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nosuid)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        # In iso9660 filesystems mtab could describe a "blocksize" value, this should be reflected in
        # fstab as "block".  The next variable is to satisfy shellcheck SC2050.
        fs_type=""
        if [  "$fs_type" == "iso9660" ] ; then
            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< "$previous_mount_opts")
        fi
        echo " /home  defaults,${previous_mount_opts}nosuid 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep -q "nosuid"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nosuid|" /etc/fstab
    fi


    if mkdir -p "/home"; then
        if mountpoint -q "/home"; then
            mount -o remount --target "/home"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_mount_option_home_nosuid'

# ── FIXING: Mount Option Tmp Nodev ──
# Rule: xccdf_org.ssgproject.content_rule_mount_option_tmp_nodev
# BEGIN fix (195 / 379) for 'xccdf_org.ssgproject.content_rule_mount_option_tmp_nodev'
###############################################################################
(>&2 echo "Remediating rule 195/379: 'xccdf_org.ssgproject.content_rule_mount_option_tmp_nodev'"); (
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ) && { findmnt --kernel "/tmp" > /dev/null || findmnt --fstab "/tmp" > /dev/null; }; then

function perform_remediation {
    
        # the mount point /tmp has to be defined in /etc/fstab
        # before this remediation can be executed. In case it is not defined, the
        # remediation aborts and no changes regarding the mount point are done.
        mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" "/tmp")"

    grep "$mount_point_match_regexp" -q /etc/fstab \
        || { echo "The mount point '/tmp' is not even in /etc/fstab, so we can't set up mount options" >&2;
                echo "Not remediating, because there is no record of /tmp in /etc/fstab" >&2; return 1; }
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /tmp)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nodev)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        # In iso9660 filesystems mtab could describe a "blocksize" value, this should be reflected in
        # fstab as "block".  The next variable is to satisfy shellcheck SC2050.
        fs_type=""
        if [  "$fs_type" == "iso9660" ] ; then
            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< "$previous_mount_opts")
        fi
        echo " /tmp  defaults,${previous_mount_opts}nodev 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep -q "nodev"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nodev|" /etc/fstab
    fi


    if mkdir -p "/tmp"; then
        if mountpoint -q "/tmp"; then
            mount -o remount --target "/tmp"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_mount_option_tmp_nodev'

# ── FIXING: Mount Option Tmp Noexec ──
# Rule: xccdf_org.ssgproject.content_rule_mount_option_tmp_noexec
# BEGIN fix (196 / 379) for 'xccdf_org.ssgproject.content_rule_mount_option_tmp_noexec'
###############################################################################
(>&2 echo "Remediating rule 196/379: 'xccdf_org.ssgproject.content_rule_mount_option_tmp_noexec'"); (
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ) && { findmnt --kernel "/tmp" > /dev/null || findmnt --fstab "/tmp" > /dev/null; }; then

function perform_remediation {
    
        # the mount point /tmp has to be defined in /etc/fstab
        # before this remediation can be executed. In case it is not defined, the
        # remediation aborts and no changes regarding the mount point are done.
        mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" "/tmp")"

    grep "$mount_point_match_regexp" -q /etc/fstab \
        || { echo "The mount point '/tmp' is not even in /etc/fstab, so we can't set up mount options" >&2;
                echo "Not remediating, because there is no record of /tmp in /etc/fstab" >&2; return 1; }
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /tmp)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|noexec)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        # In iso9660 filesystems mtab could describe a "blocksize" value, this should be reflected in
        # fstab as "block".  The next variable is to satisfy shellcheck SC2050.
        fs_type=""
        if [  "$fs_type" == "iso9660" ] ; then
            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< "$previous_mount_opts")
        fi
        echo " /tmp  defaults,${previous_mount_opts}noexec 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep -q "noexec"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,noexec|" /etc/fstab
    fi


    if mkdir -p "/tmp"; then
        if mountpoint -q "/tmp"; then
            mount -o remount --target "/tmp"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_mount_option_tmp_noexec'

# ── FIXING: Mount Option Tmp Nosuid ──
# Rule: xccdf_org.ssgproject.content_rule_mount_option_tmp_nosuid
# BEGIN fix (197 / 379) for 'xccdf_org.ssgproject.content_rule_mount_option_tmp_nosuid'
###############################################################################
(>&2 echo "Remediating rule 197/379: 'xccdf_org.ssgproject.content_rule_mount_option_tmp_nosuid'"); (
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ) && { findmnt --kernel "/tmp" > /dev/null || findmnt --fstab "/tmp" > /dev/null; }; then

function perform_remediation {
    
        # the mount point /tmp has to be defined in /etc/fstab
        # before this remediation can be executed. In case it is not defined, the
        # remediation aborts and no changes regarding the mount point are done.
        mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" "/tmp")"

    grep "$mount_point_match_regexp" -q /etc/fstab \
        || { echo "The mount point '/tmp' is not even in /etc/fstab, so we can't set up mount options" >&2;
                echo "Not remediating, because there is no record of /tmp in /etc/fstab" >&2; return 1; }
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /tmp)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nosuid)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        # In iso9660 filesystems mtab could describe a "blocksize" value, this should be reflected in
        # fstab as "block".  The next variable is to satisfy shellcheck SC2050.
        fs_type=""
        if [  "$fs_type" == "iso9660" ] ; then
            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< "$previous_mount_opts")
        fi
        echo " /tmp  defaults,${previous_mount_opts}nosuid 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep -q "nosuid"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nosuid|" /etc/fstab
    fi


    if mkdir -p "/tmp"; then
        if mountpoint -q "/tmp"; then
            mount -o remount --target "/tmp"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_mount_option_tmp_nosuid'

# ── FIXING: Mount Option Var Log Audit Nodev ──
# Rule: xccdf_org.ssgproject.content_rule_mount_option_var_log_audit_nodev
# BEGIN fix (198 / 379) for 'xccdf_org.ssgproject.content_rule_mount_option_var_log_audit_nodev'
###############################################################################
(>&2 echo "Remediating rule 198/379: 'xccdf_org.ssgproject.content_rule_mount_option_var_log_audit_nodev'"); (
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ) && { findmnt --kernel "/var/log/audit" > /dev/null || findmnt --fstab "/var/log/audit" > /dev/null; }; then

function perform_remediation {
    
        # the mount point /var/log/audit has to be defined in /etc/fstab
        # before this remediation can be executed. In case it is not defined, the
        # remediation aborts and no changes regarding the mount point are done.
        mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" "/var/log/audit")"

    grep "$mount_point_match_regexp" -q /etc/fstab \
        || { echo "The mount point '/var/log/audit' is not even in /etc/fstab, so we can't set up mount options" >&2;
                echo "Not remediating, because there is no record of /var/log/audit in /etc/fstab" >&2; return 1; }
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /var/log/audit)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nodev)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        # In iso9660 filesystems mtab could describe a "blocksize" value, this should be reflected in
        # fstab as "block".  The next variable is to satisfy shellcheck SC2050.
        fs_type=""
        if [  "$fs_type" == "iso9660" ] ; then
            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< "$previous_mount_opts")
        fi
        echo " /var/log/audit  defaults,${previous_mount_opts}nodev 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep -q "nodev"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nodev|" /etc/fstab
    fi


    if mkdir -p "/var/log/audit"; then
        if mountpoint -q "/var/log/audit"; then
            mount -o remount --target "/var/log/audit"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_mount_option_var_log_audit_nodev'

# ── FIXING: Mount Option Var Log Audit Noexec ──
# Rule: xccdf_org.ssgproject.content_rule_mount_option_var_log_audit_noexec
# BEGIN fix (199 / 379) for 'xccdf_org.ssgproject.content_rule_mount_option_var_log_audit_noexec'
###############################################################################
(>&2 echo "Remediating rule 199/379: 'xccdf_org.ssgproject.content_rule_mount_option_var_log_audit_noexec'"); (
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ) && { findmnt --kernel "/var/log/audit" > /dev/null || findmnt --fstab "/var/log/audit" > /dev/null; }; then

function perform_remediation {
    
        # the mount point /var/log/audit has to be defined in /etc/fstab
        # before this remediation can be executed. In case it is not defined, the
        # remediation aborts and no changes regarding the mount point are done.
        mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" "/var/log/audit")"

    grep "$mount_point_match_regexp" -q /etc/fstab \
        || { echo "The mount point '/var/log/audit' is not even in /etc/fstab, so we can't set up mount options" >&2;
                echo "Not remediating, because there is no record of /var/log/audit in /etc/fstab" >&2; return 1; }
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /var/log/audit)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|noexec)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        # In iso9660 filesystems mtab could describe a "blocksize" value, this should be reflected in
        # fstab as "block".  The next variable is to satisfy shellcheck SC2050.
        fs_type=""
        if [  "$fs_type" == "iso9660" ] ; then
            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< "$previous_mount_opts")
        fi
        echo " /var/log/audit  defaults,${previous_mount_opts}noexec 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep -q "noexec"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,noexec|" /etc/fstab
    fi


    if mkdir -p "/var/log/audit"; then
        if mountpoint -q "/var/log/audit"; then
            mount -o remount --target "/var/log/audit"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_mount_option_var_log_audit_noexec'

# ── FIXING: Mount Option Var Log Audit Nosuid ──
# Rule: xccdf_org.ssgproject.content_rule_mount_option_var_log_audit_nosuid
# BEGIN fix (200 / 379) for 'xccdf_org.ssgproject.content_rule_mount_option_var_log_audit_nosuid'
###############################################################################
(>&2 echo "Remediating rule 200/379: 'xccdf_org.ssgproject.content_rule_mount_option_var_log_audit_nosuid'"); (
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ) && { findmnt --kernel "/var/log/audit" > /dev/null || findmnt --fstab "/var/log/audit" > /dev/null; }; then

function perform_remediation {
    
        # the mount point /var/log/audit has to be defined in /etc/fstab
        # before this remediation can be executed. In case it is not defined, the
        # remediation aborts and no changes regarding the mount point are done.
        mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" "/var/log/audit")"

    grep "$mount_point_match_regexp" -q /etc/fstab \
        || { echo "The mount point '/var/log/audit' is not even in /etc/fstab, so we can't set up mount options" >&2;
                echo "Not remediating, because there is no record of /var/log/audit in /etc/fstab" >&2; return 1; }
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /var/log/audit)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nosuid)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        # In iso9660 filesystems mtab could describe a "blocksize" value, this should be reflected in
        # fstab as "block".  The next variable is to satisfy shellcheck SC2050.
        fs_type=""
        if [  "$fs_type" == "iso9660" ] ; then
            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< "$previous_mount_opts")
        fi
        echo " /var/log/audit  defaults,${previous_mount_opts}nosuid 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep -q "nosuid"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nosuid|" /etc/fstab
    fi


    if mkdir -p "/var/log/audit"; then
        if mountpoint -q "/var/log/audit"; then
            mount -o remount --target "/var/log/audit"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_mount_option_var_log_audit_nosuid'

# ── FIXING: Mount Option Var Log Nodev ──
# Rule: xccdf_org.ssgproject.content_rule_mount_option_var_log_nodev
# BEGIN fix (201 / 379) for 'xccdf_org.ssgproject.content_rule_mount_option_var_log_nodev'
###############################################################################
(>&2 echo "Remediating rule 201/379: 'xccdf_org.ssgproject.content_rule_mount_option_var_log_nodev'"); (
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ) && { findmnt --kernel "/var/log" > /dev/null || findmnt --fstab "/var/log" > /dev/null; }; then

function perform_remediation {
    
        # the mount point /var/log has to be defined in /etc/fstab
        # before this remediation can be executed. In case it is not defined, the
        # remediation aborts and no changes regarding the mount point are done.
        mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" "/var/log")"

    grep "$mount_point_match_regexp" -q /etc/fstab \
        || { echo "The mount point '/var/log' is not even in /etc/fstab, so we can't set up mount options" >&2;
                echo "Not remediating, because there is no record of /var/log in /etc/fstab" >&2; return 1; }
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /var/log)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nodev)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        # In iso9660 filesystems mtab could describe a "blocksize" value, this should be reflected in
        # fstab as "block".  The next variable is to satisfy shellcheck SC2050.
        fs_type=""
        if [  "$fs_type" == "iso9660" ] ; then
            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< "$previous_mount_opts")
        fi
        echo " /var/log  defaults,${previous_mount_opts}nodev 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep -q "nodev"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nodev|" /etc/fstab
    fi


    if mkdir -p "/var/log"; then
        if mountpoint -q "/var/log"; then
            mount -o remount --target "/var/log"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_mount_option_var_log_nodev'

# ── FIXING: Mount Option Var Log Noexec ──
# Rule: xccdf_org.ssgproject.content_rule_mount_option_var_log_noexec
# BEGIN fix (202 / 379) for 'xccdf_org.ssgproject.content_rule_mount_option_var_log_noexec'
###############################################################################
(>&2 echo "Remediating rule 202/379: 'xccdf_org.ssgproject.content_rule_mount_option_var_log_noexec'"); (
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ) && { findmnt --kernel "/var/log" > /dev/null || findmnt --fstab "/var/log" > /dev/null; }; then

function perform_remediation {
    
        # the mount point /var/log has to be defined in /etc/fstab
        # before this remediation can be executed. In case it is not defined, the
        # remediation aborts and no changes regarding the mount point are done.
        mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" "/var/log")"

    grep "$mount_point_match_regexp" -q /etc/fstab \
        || { echo "The mount point '/var/log' is not even in /etc/fstab, so we can't set up mount options" >&2;
                echo "Not remediating, because there is no record of /var/log in /etc/fstab" >&2; return 1; }
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /var/log)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|noexec)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        # In iso9660 filesystems mtab could describe a "blocksize" value, this should be reflected in
        # fstab as "block".  The next variable is to satisfy shellcheck SC2050.
        fs_type=""
        if [  "$fs_type" == "iso9660" ] ; then
            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< "$previous_mount_opts")
        fi
        echo " /var/log  defaults,${previous_mount_opts}noexec 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep -q "noexec"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,noexec|" /etc/fstab
    fi


    if mkdir -p "/var/log"; then
        if mountpoint -q "/var/log"; then
            mount -o remount --target "/var/log"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_mount_option_var_log_noexec'

# ── FIXING: Mount Option Var Log Nosuid ──
# Rule: xccdf_org.ssgproject.content_rule_mount_option_var_log_nosuid
# BEGIN fix (203 / 379) for 'xccdf_org.ssgproject.content_rule_mount_option_var_log_nosuid'
###############################################################################
(>&2 echo "Remediating rule 203/379: 'xccdf_org.ssgproject.content_rule_mount_option_var_log_nosuid'"); (
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ) && { findmnt --kernel "/var/log" > /dev/null || findmnt --fstab "/var/log" > /dev/null; }; then

function perform_remediation {
    
        # the mount point /var/log has to be defined in /etc/fstab
        # before this remediation can be executed. In case it is not defined, the
        # remediation aborts and no changes regarding the mount point are done.
        mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" "/var/log")"

    grep "$mount_point_match_regexp" -q /etc/fstab \
        || { echo "The mount point '/var/log' is not even in /etc/fstab, so we can't set up mount options" >&2;
                echo "Not remediating, because there is no record of /var/log in /etc/fstab" >&2; return 1; }
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /var/log)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nosuid)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        # In iso9660 filesystems mtab could describe a "blocksize" value, this should be reflected in
        # fstab as "block".  The next variable is to satisfy shellcheck SC2050.
        fs_type=""
        if [  "$fs_type" == "iso9660" ] ; then
            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< "$previous_mount_opts")
        fi
        echo " /var/log  defaults,${previous_mount_opts}nosuid 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep -q "nosuid"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nosuid|" /etc/fstab
    fi


    if mkdir -p "/var/log"; then
        if mountpoint -q "/var/log"; then
            mount -o remount --target "/var/log"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_mount_option_var_log_nosuid'

# ── FIXING: Mount Option Var Nodev ──
# Rule: xccdf_org.ssgproject.content_rule_mount_option_var_nodev
# BEGIN fix (204 / 379) for 'xccdf_org.ssgproject.content_rule_mount_option_var_nodev'
###############################################################################
(>&2 echo "Remediating rule 204/379: 'xccdf_org.ssgproject.content_rule_mount_option_var_nodev'"); (
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ) && { findmnt --kernel "/var" > /dev/null || findmnt --fstab "/var" > /dev/null; }; then

function perform_remediation {
    
        # the mount point /var has to be defined in /etc/fstab
        # before this remediation can be executed. In case it is not defined, the
        # remediation aborts and no changes regarding the mount point are done.
        mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" "/var")"

    grep "$mount_point_match_regexp" -q /etc/fstab \
        || { echo "The mount point '/var' is not even in /etc/fstab, so we can't set up mount options" >&2;
                echo "Not remediating, because there is no record of /var in /etc/fstab" >&2; return 1; }
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /var)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nodev)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        # In iso9660 filesystems mtab could describe a "blocksize" value, this should be reflected in
        # fstab as "block".  The next variable is to satisfy shellcheck SC2050.
        fs_type=""
        if [  "$fs_type" == "iso9660" ] ; then
            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< "$previous_mount_opts")
        fi
        echo " /var  defaults,${previous_mount_opts}nodev 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep -q "nodev"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nodev|" /etc/fstab
    fi


    if mkdir -p "/var"; then
        if mountpoint -q "/var"; then
            mount -o remount --target "/var"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_mount_option_var_nodev'

# ── FIXING: Mount Option Var Nosuid ──
# Rule: xccdf_org.ssgproject.content_rule_mount_option_var_nosuid
# BEGIN fix (205 / 379) for 'xccdf_org.ssgproject.content_rule_mount_option_var_nosuid'
###############################################################################
(>&2 echo "Remediating rule 205/379: 'xccdf_org.ssgproject.content_rule_mount_option_var_nosuid'"); (
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ) && { findmnt --kernel "/var" > /dev/null || findmnt --fstab "/var" > /dev/null; }; then

function perform_remediation {
    
        # the mount point /var has to be defined in /etc/fstab
        # before this remediation can be executed. In case it is not defined, the
        # remediation aborts and no changes regarding the mount point are done.
        mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" "/var")"

    grep "$mount_point_match_regexp" -q /etc/fstab \
        || { echo "The mount point '/var' is not even in /etc/fstab, so we can't set up mount options" >&2;
                echo "Not remediating, because there is no record of /var in /etc/fstab" >&2; return 1; }
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /var)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nosuid)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        # In iso9660 filesystems mtab could describe a "blocksize" value, this should be reflected in
        # fstab as "block".  The next variable is to satisfy shellcheck SC2050.
        fs_type=""
        if [  "$fs_type" == "iso9660" ] ; then
            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< "$previous_mount_opts")
        fi
        echo " /var  defaults,${previous_mount_opts}nosuid 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep -q "nosuid"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nosuid|" /etc/fstab
    fi


    if mkdir -p "/var"; then
        if mountpoint -q "/var"; then
            mount -o remount --target "/var"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_mount_option_var_nosuid'

# ── FIXING: Mount Option Var Tmp Nodev ──
# Rule: xccdf_org.ssgproject.content_rule_mount_option_var_tmp_nodev
# BEGIN fix (206 / 379) for 'xccdf_org.ssgproject.content_rule_mount_option_var_tmp_nodev'
###############################################################################
(>&2 echo "Remediating rule 206/379: 'xccdf_org.ssgproject.content_rule_mount_option_var_tmp_nodev'"); (
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ) && { findmnt --kernel "/var/tmp" > /dev/null || findmnt --fstab "/var/tmp" > /dev/null; }; then

function perform_remediation {
    
        # the mount point /var/tmp has to be defined in /etc/fstab
        # before this remediation can be executed. In case it is not defined, the
        # remediation aborts and no changes regarding the mount point are done.
        mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" "/var/tmp")"

    grep "$mount_point_match_regexp" -q /etc/fstab \
        || { echo "The mount point '/var/tmp' is not even in /etc/fstab, so we can't set up mount options" >&2;
                echo "Not remediating, because there is no record of /var/tmp in /etc/fstab" >&2; return 1; }
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /var/tmp)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nodev)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        # In iso9660 filesystems mtab could describe a "blocksize" value, this should be reflected in
        # fstab as "block".  The next variable is to satisfy shellcheck SC2050.
        fs_type=""
        if [  "$fs_type" == "iso9660" ] ; then
            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< "$previous_mount_opts")
        fi
        echo " /var/tmp  defaults,${previous_mount_opts}nodev 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep -q "nodev"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nodev|" /etc/fstab
    fi


    if mkdir -p "/var/tmp"; then
        if mountpoint -q "/var/tmp"; then
            mount -o remount --target "/var/tmp"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_mount_option_var_tmp_nodev'

# ── FIXING: Mount Option Var Tmp Noexec ──
# Rule: xccdf_org.ssgproject.content_rule_mount_option_var_tmp_noexec
# BEGIN fix (207 / 379) for 'xccdf_org.ssgproject.content_rule_mount_option_var_tmp_noexec'
###############################################################################
(>&2 echo "Remediating rule 207/379: 'xccdf_org.ssgproject.content_rule_mount_option_var_tmp_noexec'"); (
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ) && { findmnt --kernel "/var/tmp" > /dev/null || findmnt --fstab "/var/tmp" > /dev/null; }; then

function perform_remediation {
    
        # the mount point /var/tmp has to be defined in /etc/fstab
        # before this remediation can be executed. In case it is not defined, the
        # remediation aborts and no changes regarding the mount point are done.
        mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" "/var/tmp")"

    grep "$mount_point_match_regexp" -q /etc/fstab \
        || { echo "The mount point '/var/tmp' is not even in /etc/fstab, so we can't set up mount options" >&2;
                echo "Not remediating, because there is no record of /var/tmp in /etc/fstab" >&2; return 1; }
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /var/tmp)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|noexec)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        # In iso9660 filesystems mtab could describe a "blocksize" value, this should be reflected in
        # fstab as "block".  The next variable is to satisfy shellcheck SC2050.
        fs_type=""
        if [  "$fs_type" == "iso9660" ] ; then
            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< "$previous_mount_opts")
        fi
        echo " /var/tmp  defaults,${previous_mount_opts}noexec 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep -q "noexec"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,noexec|" /etc/fstab
    fi


    if mkdir -p "/var/tmp"; then
        if mountpoint -q "/var/tmp"; then
            mount -o remount --target "/var/tmp"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_mount_option_var_tmp_noexec'

# ── FIXING: Mount Option Var Tmp Nosuid ──
# Rule: xccdf_org.ssgproject.content_rule_mount_option_var_tmp_nosuid
# BEGIN fix (208 / 379) for 'xccdf_org.ssgproject.content_rule_mount_option_var_tmp_nosuid'
###############################################################################
(>&2 echo "Remediating rule 208/379: 'xccdf_org.ssgproject.content_rule_mount_option_var_tmp_nosuid'"); (
# Remediation is applicable only in certain platforms
if ( ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ) && ! ( [ -f /.dockerenv ] || [ -f /run/.containerenv ] ) ) && { findmnt --kernel "/var/tmp" > /dev/null || findmnt --fstab "/var/tmp" > /dev/null; }; then

function perform_remediation {
    
        # the mount point /var/tmp has to be defined in /etc/fstab
        # before this remediation can be executed. In case it is not defined, the
        # remediation aborts and no changes regarding the mount point are done.
        mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" "/var/tmp")"

    grep "$mount_point_match_regexp" -q /etc/fstab \
        || { echo "The mount point '/var/tmp' is not even in /etc/fstab, so we can't set up mount options" >&2;
                echo "Not remediating, because there is no record of /var/tmp in /etc/fstab" >&2; return 1; }
    


    mount_point_match_regexp="$(printf "^[[:space:]]*[^#].*[[:space:]]%s[[:space:]]" /var/tmp)"

    # If the mount point is not in /etc/fstab, get previous mount options from /etc/mtab
    if ! grep -q "$mount_point_match_regexp" /etc/fstab; then
        # runtime opts without some automatic kernel/userspace-added defaults
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/mtab | head -1 |  awk '{print $4}' \
                    | sed -E "s/(rw|defaults|seclabel|nosuid)(,|$)//g;s/,$//")
        [ "$previous_mount_opts" ] && previous_mount_opts+=","
        # In iso9660 filesystems mtab could describe a "blocksize" value, this should be reflected in
        # fstab as "block".  The next variable is to satisfy shellcheck SC2050.
        fs_type=""
        if [  "$fs_type" == "iso9660" ] ; then
            previous_mount_opts=$(sed 's/blocksize=/block=/' <<< "$previous_mount_opts")
        fi
        echo " /var/tmp  defaults,${previous_mount_opts}nosuid 0 0" >> /etc/fstab
    # If the mount_opt option is not already in the mount point's /etc/fstab entry, add it
    elif ! grep "$mount_point_match_regexp" /etc/fstab | grep -q "nosuid"; then
        previous_mount_opts=$(grep "$mount_point_match_regexp" /etc/fstab | awk '{print $4}')
        sed -i "s|\(${mount_point_match_regexp}.*${previous_mount_opts}\)|\1,nosuid|" /etc/fstab
    fi


    if mkdir -p "/var/tmp"; then
        if mountpoint -q "/var/tmp"; then
            mount -o remount --target "/var/tmp"
        fi
    fi
}

perform_remediation

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_mount_option_var_tmp_nosuid'
