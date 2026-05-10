#!/bin/bash
#
# RHEL 9 OSCAP Remediation - File & Directory Permissions and Ownership
# Description: Owner, group, and permission hardening for system files, SSH keys, audit configs, cron, GRUB, user home dirs, etc.
# Rules covered: 92
#
# Usage: Run as root: bash 04_file_permissions_and_ownership.sh
#

set -o nounset


# ── FIXING: File Groupowner Etc Issue ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_etc_issue
# BEGIN fix (34 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_issue'
###############################################################################
(>&2 echo "Remediating rule 34/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_issue'"); (
chgrp 0 /etc/issue

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_issue'

# ── FIXING: File Groupowner Etc Issue Net ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_etc_issue_net
# BEGIN fix (35 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_issue_net'
###############################################################################
(>&2 echo "Remediating rule 35/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_issue_net'"); (
chgrp 0 /etc/issue.net

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_issue_net'

# ── FIXING: File Groupowner Etc Motd ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_etc_motd
# BEGIN fix (36 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_motd'
###############################################################################
(>&2 echo "Remediating rule 36/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_motd'"); (
chgrp 0 /etc/motd

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_motd'

# ── FIXING: File Owner Etc Issue ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_etc_issue
# BEGIN fix (37 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_etc_issue'
###############################################################################
(>&2 echo "Remediating rule 37/379: 'xccdf_org.ssgproject.content_rule_file_owner_etc_issue'"); (
chown 0 /etc/issue

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_etc_issue'

# ── FIXING: File Owner Etc Issue Net ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_etc_issue_net
# BEGIN fix (38 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_etc_issue_net'
###############################################################################
(>&2 echo "Remediating rule 38/379: 'xccdf_org.ssgproject.content_rule_file_owner_etc_issue_net'"); (
chown 0 /etc/issue.net

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_etc_issue_net'

# ── FIXING: File Owner Etc Motd ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_etc_motd
# BEGIN fix (39 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_etc_motd'
###############################################################################
(>&2 echo "Remediating rule 39/379: 'xccdf_org.ssgproject.content_rule_file_owner_etc_motd'"); (
chown 0 /etc/motd

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_etc_motd'

# ── FIXING: File Permissions Etc Issue ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_etc_issue
# BEGIN fix (40 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_etc_issue'
###############################################################################
(>&2 echo "Remediating rule 40/379: 'xccdf_org.ssgproject.content_rule_file_permissions_etc_issue'"); (




chmod u-xs,g-xws,o-xwt /etc/issue

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_etc_issue'

# ── FIXING: File Permissions Etc Issue Net ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_etc_issue_net
# BEGIN fix (41 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_etc_issue_net'
###############################################################################
(>&2 echo "Remediating rule 41/379: 'xccdf_org.ssgproject.content_rule_file_permissions_etc_issue_net'"); (




chmod u-xs,g-xws,o-xwt /etc/issue.net

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_etc_issue_net'

# ── FIXING: File Permissions Etc Motd ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_etc_motd
# BEGIN fix (42 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_etc_motd'
###############################################################################
(>&2 echo "Remediating rule 42/379: 'xccdf_org.ssgproject.content_rule_file_permissions_etc_motd'"); (




chmod u-xs,g-xws,o-xwt /etc/motd

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_etc_motd'

# ── FIXING: File Permission User Init Files ──
# Rule: xccdf_org.ssgproject.content_rule_file_permission_user_init_files
# BEGIN fix (93 / 379) for 'xccdf_org.ssgproject.content_rule_file_permission_user_init_files'
###############################################################################
(>&2 echo "Remediating rule 93/379: 'xccdf_org.ssgproject.content_rule_file_permission_user_init_files'"); (

var_user_initialization_files_regex='^\.[\w\- ]+$'


readarray -t interactive_users < <(awk -F: '$3>=1000   {print $1}' /etc/passwd)
readarray -t interactive_users_home < <(awk -F: '$3>=1000   {print $6}' /etc/passwd)
readarray -t interactive_users_shell < <(awk -F: '$3>=1000   {print $7}' /etc/passwd)

USERS_IGNORED_REGEX='nobody|nfsnobody'

for (( i=0; i<"${#interactive_users[@]}"; i++ )); do
    if ! grep -qP "$USERS_IGNORED_REGEX" <<< "${interactive_users[$i]}" && \
        [ "${interactive_users_shell[$i]}" != "/sbin/nologin" ]; then
        
        readarray -t init_files < <(find "${interactive_users_home[$i]}" -maxdepth 1 \
            -exec basename {} \; | grep -P "$var_user_initialization_files_regex")
        for file in "${init_files[@]}"; do
            chmod u-s,g-wxs,o= "${interactive_users_home[$i]}/$file"
        done
    fi
done

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permission_user_init_files'

# ── FIXING: File Permissions Home Directories ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_home_directories
# BEGIN fix (94 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_home_directories'
###############################################################################
(>&2 echo "Remediating rule 94/379: 'xccdf_org.ssgproject.content_rule_file_permissions_home_directories'"); (

for home_dir in $(awk -F':' '{ if ($3 >= 1000 && $3 != 65534 && $6 != "/") print $6 }' /etc/passwd); do
    # Only update the permissions when necessary. This will avoid changing the inode timestamp when
    # the permission is already defined as expected, therefore not impacting in possible integrity
    # check systems that also check inodes timestamps.
    find "$home_dir" -maxdepth 0 -perm /7027 \! -type l -exec chmod u-s,g-w-s,o=- {} \;
done

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_home_directories'

# ── FIXING: File Groupowner Grub2 Cfg ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_grub2_cfg
# BEGIN fix (100 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_grub2_cfg'
###############################################################################
(>&2 echo "Remediating rule 100/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_grub2_cfg'"); (
# Remediation is applicable only in certain platforms
if ( rpm --quiet -q grub2-common && rpm --quiet -q kernel ) && [ ! -d /sys/firmware/efi ] && { ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ); }; then

chgrp 0 /boot/grub2/grub.cfg

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_grub2_cfg'

# ── FIXING: File Groupowner User Cfg ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_user_cfg
# BEGIN fix (101 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_user_cfg'
###############################################################################
(>&2 echo "Remediating rule 101/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_user_cfg'"); (
# Remediation is applicable only in certain platforms
if ( rpm --quiet -q grub2-common && rpm --quiet -q kernel ) && [ ! -d /sys/firmware/efi ] && { ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ); }; then

chgrp 0 /boot/grub2/user.cfg

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_user_cfg'

# ── FIXING: File Owner Grub2 Cfg ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_grub2_cfg
# BEGIN fix (102 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_grub2_cfg'
###############################################################################
(>&2 echo "Remediating rule 102/379: 'xccdf_org.ssgproject.content_rule_file_owner_grub2_cfg'"); (
# Remediation is applicable only in certain platforms
if ( rpm --quiet -q grub2-common && rpm --quiet -q kernel ) && [ ! -d /sys/firmware/efi ] && { ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ); }; then

chown 0 /boot/grub2/grub.cfg

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_grub2_cfg'

# ── FIXING: File Owner User Cfg ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_user_cfg
# BEGIN fix (103 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_user_cfg'
###############################################################################
(>&2 echo "Remediating rule 103/379: 'xccdf_org.ssgproject.content_rule_file_owner_user_cfg'"); (
# Remediation is applicable only in certain platforms
if ( rpm --quiet -q grub2-common && rpm --quiet -q kernel ) && [ ! -d /sys/firmware/efi ] && { ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ); }; then

chown 0 /boot/grub2/user.cfg

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_user_cfg'

# ── FIXING: File Permissions Grub2 Cfg ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_grub2_cfg
# BEGIN fix (104 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_grub2_cfg'
###############################################################################
(>&2 echo "Remediating rule 104/379: 'xccdf_org.ssgproject.content_rule_file_permissions_grub2_cfg'"); (
# Remediation is applicable only in certain platforms
if ( rpm --quiet -q grub2-common && rpm --quiet -q kernel ) && [ ! -d /sys/firmware/efi ] && { ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ); }; then

chmod u-xs,g-xwrs,o-xwrt /boot/grub2/grub.cfg

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_grub2_cfg'

# ── FIXING: File Permissions User Cfg ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_user_cfg
# BEGIN fix (105 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_user_cfg'
###############################################################################
(>&2 echo "Remediating rule 105/379: 'xccdf_org.ssgproject.content_rule_file_permissions_user_cfg'"); (
# Remediation is applicable only in certain platforms
if ( rpm --quiet -q grub2-common && rpm --quiet -q kernel ) && [ ! -d /sys/firmware/efi ] && { ! ( { rpm --quiet -q kernel ;} && { rpm --quiet -q rpm-ostree ;} && { rpm --quiet -q bootc ;} && { ! rpm --quiet -q openshift-kubelet ;} ); }; then

chmod u-xs,g-xwrs,o-xwrt /boot/grub2/user.cfg

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_user_cfg'

# ── FIXING: Rsyslog Files Groupownership ──
# Rule: xccdf_org.ssgproject.content_rule_rsyslog_files_groupownership
# BEGIN fix (107 / 379) for 'xccdf_org.ssgproject.content_rule_rsyslog_files_groupownership'
###############################################################################
(>&2 echo "Remediating rule 107/379: 'xccdf_org.ssgproject.content_rule_rsyslog_files_groupownership'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && rpm --quiet -q rsyslog; then

# List of log file paths to be inspected for correct permissions
# * Primarily inspect log file paths listed in /etc/rsyslog.conf
RSYSLOG_ETC_CONFIG="/etc/rsyslog.conf"
# * And also the log file paths listed after rsyslog's $IncludeConfig directive
#   (store the result into array for the case there's shell glob used as value of IncludeConfig)
readarray -t OLD_INC < <(grep -e "\$IncludeConfig[[:space:]]\+[^[:space:];]\+" /etc/rsyslog.conf | cut -d ' ' -f 2)
readarray -t RSYSLOG_INCLUDE_CONFIG < <(for INCPATH in "${OLD_INC[@]}"; do eval printf '%s\\n' "${INCPATH}"; done)
readarray -t NEW_INC < <(sed -n '/^\s*include(/,/)/Ip' /etc/rsyslog.conf | sed -n 's@.*file\s*=\s*"\([/[:alnum:][:punct:]]*\)".*@\1@Ip')
readarray -t RSYSLOG_INCLUDE < <(for INCPATH in "${NEW_INC[@]}"; do eval printf '%s\\n' "${INCPATH}"; done)

# Declare an array to hold the final list of different log file paths
declare -a LOG_FILE_PATHS

# Array to hold all rsyslog config entries
RSYSLOG_CONFIGS=()
RSYSLOG_CONFIGS=("${RSYSLOG_ETC_CONFIG}" "${RSYSLOG_INCLUDE_CONFIG[@]}" "${RSYSLOG_INCLUDE[@]}")

# Get full list of files to be checked
# RSYSLOG_CONFIGS may contain globs such as
# /etc/rsyslog.d/*.conf /etc/rsyslog.d/*.frule
# So, loop over the entries in RSYSLOG_CONFIGS and use find to get the list of included files.
RSYSLOG_CONFIG_FILES=()
for ENTRY in "${RSYSLOG_CONFIGS[@]}"
do
	# If directory, rsyslog will search for config files in recursively.
	# However, files in hidden sub-directories or hidden files will be ignored.
	if [ -d "${ENTRY}" ]
	then
		readarray -t FINDOUT < <(find "${ENTRY}" -not -path '*/.*' -type f)
		RSYSLOG_CONFIG_FILES+=("${FINDOUT[@]}")
	elif [ -f "${ENTRY}" ]
	then
		RSYSLOG_CONFIG_FILES+=("${ENTRY}")
	else
		echo "Invalid include object: ${ENTRY}"
	fi
done

# Browse each file selected above as containing paths of log files
# ('/etc/rsyslog.conf' and '/etc/rsyslog.d/*.conf' in the default configuration)
for LOG_FILE in "${RSYSLOG_CONFIG_FILES[@]}"
do
	# From each of these files extract just particular log file path(s), thus:
	# * Ignore lines starting with space (' '), comment ('#"), or variable syntax ('$') characters,
	# * Ignore empty lines,
	# * Strip quotes and closing brackets from paths.
	# * Ignore paths that match /dev|/etc.*\.conf, as those are paths, but likely not log files
	# * From the remaining valid rows select only fields constituting a log file path
	# Text file column is understood to represent a log file path if and only if all of the
	# following are met:
	# * it contains at least one slash '/' character,
	# * it is preceded by space
	# * it doesn't contain space (' '), colon (':'), and semicolon (';') characters
	# Search log file for path(s) only in case it exists!
	if [[ -f "${LOG_FILE}" ]]
	then
		NORMALIZED_CONFIG_FILE_LINES=$(sed -e "/^[#|$]/d" "${LOG_FILE}")
		LINES_WITH_PATHS=$(grep '[^/]*\s\+\S*/\S\+$' <<< "${NORMALIZED_CONFIG_FILE_LINES}")
		FILTERED_PATHS=$(awk '{if(NF>=2&&($NF~/^\//||$NF~/^-\//)){sub(/^-\//,"/",$NF);print $NF}}' <<< "${LINES_WITH_PATHS}")
		CLEANED_PATHS=$(sed -e "s/[\"')]//g; /\\/etc.*\.conf/d; /\\/dev\\//d" <<< "${FILTERED_PATHS}")
		MATCHED_ITEMS=$(sed -e "/^$/d" <<< "${CLEANED_PATHS}")
		# Since above sed command might return more than one item (delimited by newline), split
		# the particular matches entries into new array specific for this log file
		readarray -t ARRAY_FOR_LOG_FILE <<< "$MATCHED_ITEMS"
		# Concatenate the two arrays - previous content of $LOG_FILE_PATHS array with
		# items from newly created array for this log file
		LOG_FILE_PATHS+=("${ARRAY_FOR_LOG_FILE[@]}")
		# Delete the temporary array
		unset ARRAY_FOR_LOG_FILE
	fi
done

# Check for RainerScript action log format which might be also multiline so grep regex is a bit
# curly:
# extract possibly multiline action omfile expressions
# extract File="logfile" expression
# match only "logfile" expression
for LOG_FILE in "${RSYSLOG_CONFIG_FILES[@]}"
do
	ACTION_OMFILE_LINES=$(grep -iozP "action\s*\(\s*type\s*=\s*\"omfile\"[^\)]*\)" "${LOG_FILE}")
	OMFILE_LINES=$(echo "${ACTION_OMFILE_LINES}"| grep -iaoP "\bFile\s*=\s*\"([/[:alnum:][:punct:]]*)\"\s*\)")
	LOG_FILE_PATHS+=("$(echo "${OMFILE_LINES}"| grep -oE "\"([/[:alnum:][:punct:]]*)\""|tr -d "\"")")
done

# Ensure the correct attribute if file exists
FILE_CMD="chgrp"
for LOG_FILE_PATH in "${LOG_FILE_PATHS[@]}"
do
	# Sanity check - if particular $LOG_FILE_PATH is empty string, skip it from further processing
	if [ -z "$LOG_FILE_PATH" ]
	then
		continue
	fi
	$FILE_CMD "root" "$LOG_FILE_PATH"
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_rsyslog_files_groupownership'

# ── FIXING: Rsyslog Files Ownership ──
# Rule: xccdf_org.ssgproject.content_rule_rsyslog_files_ownership
# BEGIN fix (108 / 379) for 'xccdf_org.ssgproject.content_rule_rsyslog_files_ownership'
###############################################################################
(>&2 echo "Remediating rule 108/379: 'xccdf_org.ssgproject.content_rule_rsyslog_files_ownership'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && rpm --quiet -q rsyslog; then

# List of log file paths to be inspected for correct permissions
# * Primarily inspect log file paths listed in /etc/rsyslog.conf
RSYSLOG_ETC_CONFIG="/etc/rsyslog.conf"
# * And also the log file paths listed after rsyslog's $IncludeConfig directive
#   (store the result into array for the case there's shell glob used as value of IncludeConfig)
readarray -t OLD_INC < <(grep -e "\$IncludeConfig[[:space:]]\+[^[:space:];]\+" /etc/rsyslog.conf | cut -d ' ' -f 2)
readarray -t RSYSLOG_INCLUDE_CONFIG < <(for INCPATH in "${OLD_INC[@]}"; do eval printf '%s\\n' "${INCPATH}"; done)
readarray -t NEW_INC < <(sed -n '/^\s*include(/,/)/Ip' /etc/rsyslog.conf | sed -n 's@.*file\s*=\s*"\([/[:alnum:][:punct:]]*\)".*@\1@Ip')
readarray -t RSYSLOG_INCLUDE < <(for INCPATH in "${NEW_INC[@]}"; do eval printf '%s\\n' "${INCPATH}"; done)

# Declare an array to hold the final list of different log file paths
declare -a LOG_FILE_PATHS

# Array to hold all rsyslog config entries
RSYSLOG_CONFIGS=()
RSYSLOG_CONFIGS=("${RSYSLOG_ETC_CONFIG}" "${RSYSLOG_INCLUDE_CONFIG[@]}" "${RSYSLOG_INCLUDE[@]}")

# Get full list of files to be checked
# RSYSLOG_CONFIGS may contain globs such as
# /etc/rsyslog.d/*.conf /etc/rsyslog.d/*.frule
# So, loop over the entries in RSYSLOG_CONFIGS and use find to get the list of included files.
RSYSLOG_CONFIG_FILES=()
for ENTRY in "${RSYSLOG_CONFIGS[@]}"
do
	# If directory, rsyslog will search for config files in recursively.
	# However, files in hidden sub-directories or hidden files will be ignored.
	if [ -d "${ENTRY}" ]
	then
		readarray -t FINDOUT < <(find "${ENTRY}" -not -path '*/.*' -type f)
		RSYSLOG_CONFIG_FILES+=("${FINDOUT[@]}")
	elif [ -f "${ENTRY}" ]
	then
		RSYSLOG_CONFIG_FILES+=("${ENTRY}")
	else
		echo "Invalid include object: ${ENTRY}"
	fi
done

# Browse each file selected above as containing paths of log files
# ('/etc/rsyslog.conf' and '/etc/rsyslog.d/*.conf' in the default configuration)
for LOG_FILE in "${RSYSLOG_CONFIG_FILES[@]}"
do
	# From each of these files extract just particular log file path(s), thus:
	# * Ignore lines starting with space (' '), comment ('#"), or variable syntax ('$') characters,
	# * Ignore empty lines,
	# * Strip quotes and closing brackets from paths.
	# * Ignore paths that match /dev|/etc.*\.conf, as those are paths, but likely not log files
	# * From the remaining valid rows select only fields constituting a log file path
	# Text file column is understood to represent a log file path if and only if all of the
	# following are met:
	# * it contains at least one slash '/' character,
	# * it is preceded by space
	# * it doesn't contain space (' '), colon (':'), and semicolon (';') characters
	# Search log file for path(s) only in case it exists!
	if [[ -f "${LOG_FILE}" ]]
	then
		NORMALIZED_CONFIG_FILE_LINES=$(sed -e "/^[#|$]/d" "${LOG_FILE}")
		LINES_WITH_PATHS=$(grep '[^/]*\s\+\S*/\S\+$' <<< "${NORMALIZED_CONFIG_FILE_LINES}")
		FILTERED_PATHS=$(awk '{if(NF>=2&&($NF~/^\//||$NF~/^-\//)){sub(/^-\//,"/",$NF);print $NF}}' <<< "${LINES_WITH_PATHS}")
		CLEANED_PATHS=$(sed -e "s/[\"')]//g; /\\/etc.*\.conf/d; /\\/dev\\//d" <<< "${FILTERED_PATHS}")
		MATCHED_ITEMS=$(sed -e "/^$/d" <<< "${CLEANED_PATHS}")
		# Since above sed command might return more than one item (delimited by newline), split
		# the particular matches entries into new array specific for this log file
		readarray -t ARRAY_FOR_LOG_FILE <<< "$MATCHED_ITEMS"
		# Concatenate the two arrays - previous content of $LOG_FILE_PATHS array with
		# items from newly created array for this log file
		LOG_FILE_PATHS+=("${ARRAY_FOR_LOG_FILE[@]}")
		# Delete the temporary array
		unset ARRAY_FOR_LOG_FILE
	fi
done

# Check for RainerScript action log format which might be also multiline so grep regex is a bit
# curly:
# extract possibly multiline action omfile expressions
# extract File="logfile" expression
# match only "logfile" expression
for LOG_FILE in "${RSYSLOG_CONFIG_FILES[@]}"
do
	ACTION_OMFILE_LINES=$(grep -iozP "action\s*\(\s*type\s*=\s*\"omfile\"[^\)]*\)" "${LOG_FILE}")
	OMFILE_LINES=$(echo "${ACTION_OMFILE_LINES}"| grep -iaoP "\bFile\s*=\s*\"([/[:alnum:][:punct:]]*)\"\s*\)")
	LOG_FILE_PATHS+=("$(echo "${OMFILE_LINES}"| grep -oE "\"([/[:alnum:][:punct:]]*)\""|tr -d "\"")")
done

# Ensure the correct attribute if file exists
FILE_CMD="chown"
for LOG_FILE_PATH in "${LOG_FILE_PATHS[@]}"
do
	# Sanity check - if particular $LOG_FILE_PATH is empty string, skip it from further processing
	if [ -z "$LOG_FILE_PATH" ]
	then
		continue
	fi
	$FILE_CMD "root" "$LOG_FILE_PATH"
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_rsyslog_files_ownership'

# ── FIXING: Rsyslog Files Permissions ──
# Rule: xccdf_org.ssgproject.content_rule_rsyslog_files_permissions
# BEGIN fix (109 / 379) for 'xccdf_org.ssgproject.content_rule_rsyslog_files_permissions'
###############################################################################
(>&2 echo "Remediating rule 109/379: 'xccdf_org.ssgproject.content_rule_rsyslog_files_permissions'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && rpm --quiet -q rsyslog; then

# List of log file paths to be inspected for correct permissions
# * Primarily inspect log file paths listed in /etc/rsyslog.conf
RSYSLOG_ETC_CONFIG="/etc/rsyslog.conf"
# * And also the log file paths listed after rsyslog's $IncludeConfig directive
#   (store the result into array for the case there's shell glob used as value of IncludeConfig)
readarray -t OLD_INC < <(grep -e "\$IncludeConfig[[:space:]]\+[^[:space:];]\+" /etc/rsyslog.conf | cut -d ' ' -f 2)
readarray -t RSYSLOG_INCLUDE_CONFIG < <(for INCPATH in "${OLD_INC[@]}"; do eval printf '%s\\n' "${INCPATH}"; done)
readarray -t NEW_INC < <(sed -n '/^\s*include(/,/)/Ip' /etc/rsyslog.conf | sed -n 's@.*file\s*=\s*"\([/[:alnum:][:punct:]]*\)".*@\1@Ip')
readarray -t RSYSLOG_INCLUDE < <(for INCPATH in "${NEW_INC[@]}"; do eval printf '%s\\n' "${INCPATH}"; done)

# Declare an array to hold the final list of different log file paths
declare -a LOG_FILE_PATHS

# Array to hold all rsyslog config entries
RSYSLOG_CONFIGS=()
RSYSLOG_CONFIGS=("${RSYSLOG_ETC_CONFIG}" "${RSYSLOG_INCLUDE_CONFIG[@]}" "${RSYSLOG_INCLUDE[@]}")

# Get full list of files to be checked
# RSYSLOG_CONFIGS may contain globs such as
# /etc/rsyslog.d/*.conf /etc/rsyslog.d/*.frule
# So, loop over the entries in RSYSLOG_CONFIGS and use find to get the list of included files.
RSYSLOG_CONFIG_FILES=()
for ENTRY in "${RSYSLOG_CONFIGS[@]}"
do
	# If directory, rsyslog will search for config files in recursively.
	# However, files in hidden sub-directories or hidden files will be ignored.
	if [ -d "${ENTRY}" ]
	then
		readarray -t FINDOUT < <(find "${ENTRY}" -not -path '*/.*' -type f)
		RSYSLOG_CONFIG_FILES+=("${FINDOUT[@]}")
	elif [ -f "${ENTRY}" ]
	then
		RSYSLOG_CONFIG_FILES+=("${ENTRY}")
	else
		echo "Invalid include object: ${ENTRY}"
	fi
done

# Browse each file selected above as containing paths of log files
# ('/etc/rsyslog.conf' and '/etc/rsyslog.d/*.conf' in the default configuration)
for LOG_FILE in "${RSYSLOG_CONFIG_FILES[@]}"
do
	# From each of these files extract just particular log file path(s), thus:
	# * Ignore lines starting with space (' '), comment ('#"), or variable syntax ('$') characters,
	# * Ignore empty lines,
	# * Strip quotes and closing brackets from paths.
	# * Ignore paths that match /dev|/etc.*\.conf, as those are paths, but likely not log files
	# * From the remaining valid rows select only fields constituting a log file path
	# Text file column is understood to represent a log file path if and only if all of the
	# following are met:
	# * it contains at least one slash '/' character,
	# * it is preceded by space
	# * it doesn't contain space (' '), colon (':'), and semicolon (';') characters
	# Search log file for path(s) only in case it exists!
	if [[ -f "${LOG_FILE}" ]]
	then
		NORMALIZED_CONFIG_FILE_LINES=$(sed -e "/^[#|$]/d" "${LOG_FILE}")
		LINES_WITH_PATHS=$(grep '[^/]*\s\+\S*/\S\+$' <<< "${NORMALIZED_CONFIG_FILE_LINES}")
		FILTERED_PATHS=$(awk '{if(NF>=2&&($NF~/^\//||$NF~/^-\//)){sub(/^-\//,"/",$NF);print $NF}}' <<< "${LINES_WITH_PATHS}")
		CLEANED_PATHS=$(sed -e "s/[\"')]//g; /\\/etc.*\.conf/d; /\\/dev\\//d" <<< "${FILTERED_PATHS}")
		MATCHED_ITEMS=$(sed -e "/^$/d" <<< "${CLEANED_PATHS}")
		# Since above sed command might return more than one item (delimited by newline), split
		# the particular matches entries into new array specific for this log file
		readarray -t ARRAY_FOR_LOG_FILE <<< "$MATCHED_ITEMS"
		# Concatenate the two arrays - previous content of $LOG_FILE_PATHS array with
		# items from newly created array for this log file
		LOG_FILE_PATHS+=("${ARRAY_FOR_LOG_FILE[@]}")
		# Delete the temporary array
		unset ARRAY_FOR_LOG_FILE
	fi
done

# Check for RainerScript action log format which might be also multiline so grep regex is a bit
# curly:
# extract possibly multiline action omfile expressions
# extract File="logfile" expression
# match only "logfile" expression
for LOG_FILE in "${RSYSLOG_CONFIG_FILES[@]}"
do
	ACTION_OMFILE_LINES=$(grep -iozP "action\s*\(\s*type\s*=\s*\"omfile\"[^\)]*\)" "${LOG_FILE}")
	OMFILE_LINES=$(echo "${ACTION_OMFILE_LINES}"| grep -iaoP "\bFile\s*=\s*\"([/[:alnum:][:punct:]]*)\"\s*\)")
	LOG_FILE_PATHS+=("$(echo "${OMFILE_LINES}"| grep -oE "\"([/[:alnum:][:punct:]]*)\""|tr -d "\"")")
done

# Ensure the correct attribute if file exists
FILE_CMD="chmod"
for LOG_FILE_PATH in "${LOG_FILE_PATHS[@]}"
do
	# Sanity check - if particular $LOG_FILE_PATH is empty string, skip it from further processing
	if [ -z "$LOG_FILE_PATH" ]
	then
		continue
	fi
	$FILE_CMD "0640" "$LOG_FILE_PATH"
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_rsyslog_files_permissions'

# ── FIXING: File Permissions Unauthorized World Writable ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_unauthorized_world_writable
# BEGIN fix (150 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_unauthorized_world_writable'
###############################################################################
(>&2 echo "Remediating rule 150/379: 'xccdf_org.ssgproject.content_rule_file_permissions_unauthorized_world_writable'"); (

FILTER_NODEV=$(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,)

# Do not consider /sysroot partition because it contains only the physical
# read-only root on bootable containers.
PARTITIONS=$(findmnt -n -l -k -it $FILTER_NODEV | awk '{ print $1 }' | grep -v "/sysroot")

for PARTITION in $PARTITIONS; do
  find "${PARTITION}" -xdev -type f -perm -002 -exec chmod o-w {} \; 2>/dev/null
done

# Ensure /tmp is also fixed when tmpfs is used.
if grep "^tmpfs /tmp" /proc/mounts; then
  find /tmp -xdev -type f -perm -002 -exec chmod o-w {} \; 2>/dev/null
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_unauthorized_world_writable'

# ── FIXING: File Permissions Ungroupowned ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_ungroupowned
# BEGIN fix (151 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_ungroupowned'
###############################################################################
(>&2 echo "Remediating rule 151/379: 'xccdf_org.ssgproject.content_rule_file_permissions_ungroupowned'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_file_permissions_ungroupowned' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_ungroupowned'

# ── FIXING: No Files Unowned By User ──
# Rule: xccdf_org.ssgproject.content_rule_no_files_unowned_by_user
# BEGIN fix (152 / 379) for 'xccdf_org.ssgproject.content_rule_no_files_unowned_by_user'
###############################################################################
(>&2 echo "Remediating rule 152/379: 'xccdf_org.ssgproject.content_rule_no_files_unowned_by_user'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_no_files_unowned_by_user' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_no_files_unowned_by_user'

# ── FIXING: File Etc Security Opasswd ──
# Rule: xccdf_org.ssgproject.content_rule_file_etc_security_opasswd
# BEGIN fix (153 / 379) for 'xccdf_org.ssgproject.content_rule_file_etc_security_opasswd'
###############################################################################
(>&2 echo "Remediating rule 153/379: 'xccdf_org.ssgproject.content_rule_file_etc_security_opasswd'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_file_etc_security_opasswd' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_file_etc_security_opasswd'

# ── FIXING: File Groupowner Backup Etc Group ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_backup_etc_group
# BEGIN fix (154 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_backup_etc_group'
###############################################################################
(>&2 echo "Remediating rule 154/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_backup_etc_group'"); (
chgrp 0 /etc/group-

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_backup_etc_group'

# ── FIXING: File Groupowner Backup Etc Gshadow ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_backup_etc_gshadow
# BEGIN fix (155 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_backup_etc_gshadow'
###############################################################################
(>&2 echo "Remediating rule 155/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_backup_etc_gshadow'"); (
chgrp 0 /etc/gshadow-

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_backup_etc_gshadow'

# ── FIXING: File Groupowner Backup Etc Passwd ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_backup_etc_passwd
# BEGIN fix (156 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_backup_etc_passwd'
###############################################################################
(>&2 echo "Remediating rule 156/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_backup_etc_passwd'"); (
chgrp 0 /etc/passwd-

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_backup_etc_passwd'

# ── FIXING: File Groupowner Backup Etc Shadow ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_backup_etc_shadow
# BEGIN fix (157 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_backup_etc_shadow'
###############################################################################
(>&2 echo "Remediating rule 157/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_backup_etc_shadow'"); (
chgrp 0 /etc/shadow-

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_backup_etc_shadow'

# ── FIXING: File Groupowner Etc Group ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_etc_group
# BEGIN fix (158 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_group'
###############################################################################
(>&2 echo "Remediating rule 158/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_group'"); (
chgrp 0 /etc/group

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_group'

# ── FIXING: File Groupowner Etc Gshadow ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_etc_gshadow
# BEGIN fix (159 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_gshadow'
###############################################################################
(>&2 echo "Remediating rule 159/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_gshadow'"); (
chgrp 0 /etc/gshadow

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_gshadow'

# ── FIXING: File Groupowner Etc Passwd ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_etc_passwd
# BEGIN fix (160 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_passwd'
###############################################################################
(>&2 echo "Remediating rule 160/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_passwd'"); (
chgrp 0 /etc/passwd

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_passwd'

# ── FIXING: File Groupowner Etc Shadow ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_etc_shadow
# BEGIN fix (161 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_shadow'
###############################################################################
(>&2 echo "Remediating rule 161/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_shadow'"); (
chgrp 0 /etc/shadow

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_shadow'

# ── FIXING: File Groupowner Etc Shells ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_etc_shells
# BEGIN fix (162 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_shells'
###############################################################################
(>&2 echo "Remediating rule 162/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_shells'"); (
chgrp 0 /etc/shells

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_etc_shells'

# ── FIXING: File Owner Backup Etc Group ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_backup_etc_group
# BEGIN fix (163 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_backup_etc_group'
###############################################################################
(>&2 echo "Remediating rule 163/379: 'xccdf_org.ssgproject.content_rule_file_owner_backup_etc_group'"); (
chown 0 /etc/group-

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_backup_etc_group'

# ── FIXING: File Owner Backup Etc Gshadow ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_backup_etc_gshadow
# BEGIN fix (164 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_backup_etc_gshadow'
###############################################################################
(>&2 echo "Remediating rule 164/379: 'xccdf_org.ssgproject.content_rule_file_owner_backup_etc_gshadow'"); (
chown 0 /etc/gshadow-

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_backup_etc_gshadow'

# ── FIXING: File Owner Backup Etc Passwd ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_backup_etc_passwd
# BEGIN fix (165 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_backup_etc_passwd'
###############################################################################
(>&2 echo "Remediating rule 165/379: 'xccdf_org.ssgproject.content_rule_file_owner_backup_etc_passwd'"); (
chown 0 /etc/passwd-

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_backup_etc_passwd'

# ── FIXING: File Owner Backup Etc Shadow ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_backup_etc_shadow
# BEGIN fix (166 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_backup_etc_shadow'
###############################################################################
(>&2 echo "Remediating rule 166/379: 'xccdf_org.ssgproject.content_rule_file_owner_backup_etc_shadow'"); (
chown 0 /etc/shadow-

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_backup_etc_shadow'

# ── FIXING: File Owner Etc Group ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_etc_group
# BEGIN fix (167 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_etc_group'
###############################################################################
(>&2 echo "Remediating rule 167/379: 'xccdf_org.ssgproject.content_rule_file_owner_etc_group'"); (
chown 0 /etc/group

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_etc_group'

# ── FIXING: File Owner Etc Gshadow ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_etc_gshadow
# BEGIN fix (168 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_etc_gshadow'
###############################################################################
(>&2 echo "Remediating rule 168/379: 'xccdf_org.ssgproject.content_rule_file_owner_etc_gshadow'"); (
chown 0 /etc/gshadow

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_etc_gshadow'

# ── FIXING: File Owner Etc Passwd ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_etc_passwd
# BEGIN fix (169 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_etc_passwd'
###############################################################################
(>&2 echo "Remediating rule 169/379: 'xccdf_org.ssgproject.content_rule_file_owner_etc_passwd'"); (
chown 0 /etc/passwd

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_etc_passwd'

# ── FIXING: File Owner Etc Shadow ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_etc_shadow
# BEGIN fix (170 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_etc_shadow'
###############################################################################
(>&2 echo "Remediating rule 170/379: 'xccdf_org.ssgproject.content_rule_file_owner_etc_shadow'"); (
chown 0 /etc/shadow

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_etc_shadow'

# ── FIXING: File Owner Etc Shells ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_etc_shells
# BEGIN fix (171 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_etc_shells'
###############################################################################
(>&2 echo "Remediating rule 171/379: 'xccdf_org.ssgproject.content_rule_file_owner_etc_shells'"); (
chown 0 /etc/shells

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_etc_shells'

# ── FIXING: File Permissions Backup Etc Group ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_backup_etc_group
# BEGIN fix (172 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_backup_etc_group'
###############################################################################
(>&2 echo "Remediating rule 172/379: 'xccdf_org.ssgproject.content_rule_file_permissions_backup_etc_group'"); (




chmod u-xs,g-xws,o-xwt /etc/group-

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_backup_etc_group'

# ── FIXING: File Permissions Backup Etc Gshadow ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_backup_etc_gshadow
# BEGIN fix (173 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_backup_etc_gshadow'
###############################################################################
(>&2 echo "Remediating rule 173/379: 'xccdf_org.ssgproject.content_rule_file_permissions_backup_etc_gshadow'"); (




chmod u-xwrs,g-xwrs,o-xwrt /etc/gshadow-

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_backup_etc_gshadow'

# ── FIXING: File Permissions Backup Etc Passwd ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_backup_etc_passwd
# BEGIN fix (174 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_backup_etc_passwd'
###############################################################################
(>&2 echo "Remediating rule 174/379: 'xccdf_org.ssgproject.content_rule_file_permissions_backup_etc_passwd'"); (




chmod u-xs,g-xws,o-xwt /etc/passwd-

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_backup_etc_passwd'

# ── FIXING: File Permissions Backup Etc Shadow ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_backup_etc_shadow
# BEGIN fix (175 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_backup_etc_shadow'
###############################################################################
(>&2 echo "Remediating rule 175/379: 'xccdf_org.ssgproject.content_rule_file_permissions_backup_etc_shadow'"); (




chmod u-xwrs,g-xwrs,o-xwrt /etc/shadow-

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_backup_etc_shadow'

# ── FIXING: File Permissions Etc Group ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_etc_group
# BEGIN fix (176 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_etc_group'
###############################################################################
(>&2 echo "Remediating rule 176/379: 'xccdf_org.ssgproject.content_rule_file_permissions_etc_group'"); (




chmod u-xs,g-xws,o-xwt /etc/group

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_etc_group'

# ── FIXING: File Permissions Etc Gshadow ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_etc_gshadow
# BEGIN fix (177 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_etc_gshadow'
###############################################################################
(>&2 echo "Remediating rule 177/379: 'xccdf_org.ssgproject.content_rule_file_permissions_etc_gshadow'"); (




chmod u-xwrs,g-xwrs,o-xwrt /etc/gshadow

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_etc_gshadow'

# ── FIXING: File Permissions Etc Passwd ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_etc_passwd
# BEGIN fix (178 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_etc_passwd'
###############################################################################
(>&2 echo "Remediating rule 178/379: 'xccdf_org.ssgproject.content_rule_file_permissions_etc_passwd'"); (




chmod u-xs,g-xws,o-xwt /etc/passwd

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_etc_passwd'

# ── FIXING: File Permissions Etc Shadow ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_etc_shadow
# BEGIN fix (179 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_etc_shadow'
###############################################################################
(>&2 echo "Remediating rule 179/379: 'xccdf_org.ssgproject.content_rule_file_permissions_etc_shadow'"); (




chmod u-xwrs,g-xwrs,o-xwrt /etc/shadow

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_etc_shadow'

# ── FIXING: File Permissions Etc Shells ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_etc_shells
# BEGIN fix (180 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_etc_shells'
###############################################################################
(>&2 echo "Remediating rule 180/379: 'xccdf_org.ssgproject.content_rule_file_permissions_etc_shells'"); (




chmod u-xs,g-xws,o-xwt /etc/shells

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_etc_shells'

# ── FIXING: File Groupowner Cron D ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_cron_d
# BEGIN fix (222 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_cron_d'
###############################################################################
(>&2 echo "Remediating rule 222/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_cron_d'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

find -H /etc/cron.d/ -maxdepth 1 -type d -exec chgrp -L 0 {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_cron_d'

# ── FIXING: File Groupowner Cron Daily ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_cron_daily
# BEGIN fix (223 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_cron_daily'
###############################################################################
(>&2 echo "Remediating rule 223/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_cron_daily'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

find -H /etc/cron.daily/ -maxdepth 1 -type d -exec chgrp -L 0 {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_cron_daily'

# ── FIXING: File Groupowner Cron Hourly ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_cron_hourly
# BEGIN fix (224 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_cron_hourly'
###############################################################################
(>&2 echo "Remediating rule 224/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_cron_hourly'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

find -H /etc/cron.hourly/ -maxdepth 1 -type d -exec chgrp -L 0 {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_cron_hourly'

# ── FIXING: File Groupowner Cron Monthly ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_cron_monthly
# BEGIN fix (225 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_cron_monthly'
###############################################################################
(>&2 echo "Remediating rule 225/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_cron_monthly'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

find -H /etc/cron.monthly/ -maxdepth 1 -type d -exec chgrp -L 0 {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_cron_monthly'

# ── FIXING: File Groupowner Cron Weekly ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_cron_weekly
# BEGIN fix (226 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_cron_weekly'
###############################################################################
(>&2 echo "Remediating rule 226/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_cron_weekly'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

find -H /etc/cron.weekly/ -maxdepth 1 -type d -exec chgrp -L 0 {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_cron_weekly'

# ── FIXING: File Groupowner Crontab ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_crontab
# BEGIN fix (227 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_crontab'
###############################################################################
(>&2 echo "Remediating rule 227/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_crontab'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

chgrp 0 /etc/crontab

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_crontab'

# ── FIXING: File Owner Cron D ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_cron_d
# BEGIN fix (228 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_cron_d'
###############################################################################
(>&2 echo "Remediating rule 228/379: 'xccdf_org.ssgproject.content_rule_file_owner_cron_d'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

find -H /etc/cron.d/ -maxdepth 1 -type d -exec chown -L 0 {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_cron_d'

# ── FIXING: File Owner Cron Daily ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_cron_daily
# BEGIN fix (229 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_cron_daily'
###############################################################################
(>&2 echo "Remediating rule 229/379: 'xccdf_org.ssgproject.content_rule_file_owner_cron_daily'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

find -H /etc/cron.daily/ -maxdepth 1 -type d -exec chown -L 0 {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_cron_daily'

# ── FIXING: File Owner Cron Hourly ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_cron_hourly
# BEGIN fix (230 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_cron_hourly'
###############################################################################
(>&2 echo "Remediating rule 230/379: 'xccdf_org.ssgproject.content_rule_file_owner_cron_hourly'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

find -H /etc/cron.hourly/ -maxdepth 1 -type d -exec chown -L 0 {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_cron_hourly'

# ── FIXING: File Owner Cron Monthly ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_cron_monthly
# BEGIN fix (231 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_cron_monthly'
###############################################################################
(>&2 echo "Remediating rule 231/379: 'xccdf_org.ssgproject.content_rule_file_owner_cron_monthly'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

find -H /etc/cron.monthly/ -maxdepth 1 -type d -exec chown -L 0 {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_cron_monthly'

# ── FIXING: File Owner Cron Weekly ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_cron_weekly
# BEGIN fix (232 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_cron_weekly'
###############################################################################
(>&2 echo "Remediating rule 232/379: 'xccdf_org.ssgproject.content_rule_file_owner_cron_weekly'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

find -H /etc/cron.weekly/ -maxdepth 1 -type d -exec chown -L 0 {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_cron_weekly'

# ── FIXING: File Owner Crontab ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_crontab
# BEGIN fix (233 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_crontab'
###############################################################################
(>&2 echo "Remediating rule 233/379: 'xccdf_org.ssgproject.content_rule_file_owner_crontab'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

chown 0 /etc/crontab

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_crontab'

# ── FIXING: File Permissions Cron D ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_cron_d
# BEGIN fix (234 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_cron_d'
###############################################################################
(>&2 echo "Remediating rule 234/379: 'xccdf_org.ssgproject.content_rule_file_permissions_cron_d'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

find -H /etc/cron.d/ -maxdepth 1 -perm /u+s,g+xwrs,o+xwrt -type d -exec chmod u-s,g-xwrs,o-xwrt {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_cron_d'

# ── FIXING: File Permissions Cron Daily ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_cron_daily
# BEGIN fix (235 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_cron_daily'
###############################################################################
(>&2 echo "Remediating rule 235/379: 'xccdf_org.ssgproject.content_rule_file_permissions_cron_daily'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

find -H /etc/cron.daily/ -maxdepth 1 -perm /u+s,g+xwrs,o+xwrt -type d -exec chmod u-s,g-xwrs,o-xwrt {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_cron_daily'

# ── FIXING: File Permissions Cron Hourly ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_cron_hourly
# BEGIN fix (236 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_cron_hourly'
###############################################################################
(>&2 echo "Remediating rule 236/379: 'xccdf_org.ssgproject.content_rule_file_permissions_cron_hourly'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

find -H /etc/cron.hourly/ -maxdepth 1 -perm /u+s,g+xwrs,o+xwrt -type d -exec chmod u-s,g-xwrs,o-xwrt {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_cron_hourly'

# ── FIXING: File Permissions Cron Monthly ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_cron_monthly
# BEGIN fix (237 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_cron_monthly'
###############################################################################
(>&2 echo "Remediating rule 237/379: 'xccdf_org.ssgproject.content_rule_file_permissions_cron_monthly'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

find -H /etc/cron.monthly/ -maxdepth 1 -perm /u+s,g+xwrs,o+xwrt -type d -exec chmod u-s,g-xwrs,o-xwrt {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_cron_monthly'

# ── FIXING: File Permissions Cron Weekly ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_cron_weekly
# BEGIN fix (238 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_cron_weekly'
###############################################################################
(>&2 echo "Remediating rule 238/379: 'xccdf_org.ssgproject.content_rule_file_permissions_cron_weekly'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

find -H /etc/cron.weekly/ -maxdepth 1 -perm /u+s,g+xwrs,o+xwrt -type d -exec chmod u-s,g-xwrs,o-xwrt {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_cron_weekly'

# ── FIXING: File Permissions Crontab ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_crontab
# BEGIN fix (239 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_crontab'
###############################################################################
(>&2 echo "Remediating rule 239/379: 'xccdf_org.ssgproject.content_rule_file_permissions_crontab'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

chmod u-xs,g-xwrs,o-xwrt /etc/crontab

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_crontab'

# ── FIXING: File Groupowner At Allow ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_at_allow
# BEGIN fix (243 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_at_allow'
###############################################################################
(>&2 echo "Remediating rule 243/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_at_allow'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

chgrp 0 /etc/at.allow

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_at_allow'

# ── FIXING: File Groupowner Cron Allow ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_cron_allow
# BEGIN fix (244 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_cron_allow'
###############################################################################
(>&2 echo "Remediating rule 244/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_cron_allow'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

chgrp 0 /etc/cron.allow

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_cron_allow'

# ── FIXING: File Owner Cron Allow ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_cron_allow
# BEGIN fix (245 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_cron_allow'
###############################################################################
(>&2 echo "Remediating rule 245/379: 'xccdf_org.ssgproject.content_rule_file_owner_cron_allow'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

chown 0 /etc/cron.allow

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_cron_allow'

# ── FIXING: File Permissions At Allow ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_at_allow
# BEGIN fix (246 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_at_allow'
###############################################################################
(>&2 echo "Remediating rule 246/379: 'xccdf_org.ssgproject.content_rule_file_permissions_at_allow'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

chmod u-xs,g-xwrs,o-xwrt /etc/at.allow

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_at_allow'

# ── FIXING: File Permissions Cron Allow ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_cron_allow
# BEGIN fix (247 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_cron_allow'
###############################################################################
(>&2 echo "Remediating rule 247/379: 'xccdf_org.ssgproject.content_rule_file_permissions_cron_allow'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

chmod u-xs,g-xwrs,o-xwrt /etc/cron.allow

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_cron_allow'

# ── FIXING: File Groupowner Sshd Config ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupowner_sshd_config
# BEGIN fix (277 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupowner_sshd_config'
###############################################################################
(>&2 echo "Remediating rule 277/379: 'xccdf_org.ssgproject.content_rule_file_groupowner_sshd_config'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

chgrp 0 /etc/ssh/sshd_config

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupowner_sshd_config'

# ── FIXING: File Groupownership Sshd Private Key ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupownership_sshd_private_key
# BEGIN fix (278 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupownership_sshd_private_key'
###############################################################################
(>&2 echo "Remediating rule 278/379: 'xccdf_org.ssgproject.content_rule_file_groupownership_sshd_private_key'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

find -L /etc/ssh/ -maxdepth 1 -type f ! -group ssh_keys -regextype posix-extended -regex '^.*_key$' -exec chgrp -L ssh_keys {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupownership_sshd_private_key'

# ── FIXING: File Groupownership Sshd Pub Key ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupownership_sshd_pub_key
# BEGIN fix (279 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupownership_sshd_pub_key'
###############################################################################
(>&2 echo "Remediating rule 279/379: 'xccdf_org.ssgproject.content_rule_file_groupownership_sshd_pub_key'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

find -L /etc/ssh/ -maxdepth 1 -type f ! -group 0 -regextype posix-extended -regex '^.*\.pub$' -exec chgrp -L 0 {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupownership_sshd_pub_key'

# ── FIXING: File Owner Sshd Config ──
# Rule: xccdf_org.ssgproject.content_rule_file_owner_sshd_config
# BEGIN fix (280 / 379) for 'xccdf_org.ssgproject.content_rule_file_owner_sshd_config'
###############################################################################
(>&2 echo "Remediating rule 280/379: 'xccdf_org.ssgproject.content_rule_file_owner_sshd_config'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

chown 0 /etc/ssh/sshd_config

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_owner_sshd_config'

# ── FIXING: File Ownership Sshd Private Key ──
# Rule: xccdf_org.ssgproject.content_rule_file_ownership_sshd_private_key
# BEGIN fix (281 / 379) for 'xccdf_org.ssgproject.content_rule_file_ownership_sshd_private_key'
###############################################################################
(>&2 echo "Remediating rule 281/379: 'xccdf_org.ssgproject.content_rule_file_ownership_sshd_private_key'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

find -L /etc/ssh/ -maxdepth 1 -type f ! -uid 0 -regextype posix-extended -regex '^.*_key$' -exec chown -L 0 {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_ownership_sshd_private_key'

# ── FIXING: File Ownership Sshd Pub Key ──
# Rule: xccdf_org.ssgproject.content_rule_file_ownership_sshd_pub_key
# BEGIN fix (282 / 379) for 'xccdf_org.ssgproject.content_rule_file_ownership_sshd_pub_key'
###############################################################################
(>&2 echo "Remediating rule 282/379: 'xccdf_org.ssgproject.content_rule_file_ownership_sshd_pub_key'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

find -L /etc/ssh/ -maxdepth 1 -type f ! -uid 0 -regextype posix-extended -regex '^.*\.pub$' -exec chown -L 0 {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_ownership_sshd_pub_key'

# ── FIXING: File Permissions Sshd Config ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_sshd_config
# BEGIN fix (283 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_sshd_config'
###############################################################################
(>&2 echo "Remediating rule 283/379: 'xccdf_org.ssgproject.content_rule_file_permissions_sshd_config'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

chmod u-xs,g-xwrs,o-xwrt /etc/ssh/sshd_config

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_sshd_config'

# ── FIXING: File Permissions Sshd Private Key ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_sshd_private_key
# BEGIN fix (284 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_sshd_private_key'
###############################################################################
(>&2 echo "Remediating rule 284/379: 'xccdf_org.ssgproject.content_rule_file_permissions_sshd_private_key'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

for keyfile in /etc/ssh/*_key; do
    test -f "$keyfile" || continue
    if test root:root = "$(stat -c "%U:%G" "$keyfile")"; then
    
	chmod u-xs,g-xwrs,o-xwrt "$keyfile"
    
    elif test root:ssh_keys = "$(stat -c "%U:%G" "$keyfile")"; then
	chmod u-xs,g-xws,o-xwrt "$keyfile"
    else
        echo "Key-like file '$keyfile' is owned by an unexpected user:group combination"
    fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_sshd_private_key'

# ── FIXING: File Permissions Sshd Pub Key ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_sshd_pub_key
# BEGIN fix (285 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_sshd_pub_key'
###############################################################################
(>&2 echo "Remediating rule 285/379: 'xccdf_org.ssgproject.content_rule_file_permissions_sshd_pub_key'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

find -L /etc/ssh/ -maxdepth 1 -perm /u+xs,g+xws,o+xwt  -type f -regextype posix-extended -regex '^.*\.pub$' -exec chmod u-xs,g-xws,o-xwt {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_sshd_pub_key'

# ── FIXING: File Group Ownership Var Log Audit ──
# Rule: xccdf_org.ssgproject.content_rule_file_group_ownership_var_log_audit
# BEGIN fix (325 / 379) for 'xccdf_org.ssgproject.content_rule_file_group_ownership_var_log_audit'
###############################################################################
(>&2 echo "Remediating rule 325/379: 'xccdf_org.ssgproject.content_rule_file_group_ownership_var_log_audit'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

if LC_ALL=C grep -iw log_file /etc/audit/auditd.conf; then
  FILE=$(awk -F "=" '/^log_file/ {print $2}' /etc/audit/auditd.conf | tr -d ' ')
else
  FILE="/var/log/audit/audit.log"
fi


if LC_ALL=C grep -m 1 -q ^log_group /etc/audit/auditd.conf; then
  GROUP=$(awk -F "=" '/log_group/ {print $2}' /etc/audit/auditd.conf | tr -d ' ')
    if ! [ "${GROUP}" == 'root' ]; then
      chgrp ${GROUP} $FILE*
    else
      chgrp root $FILE*
    fi
else
  chgrp root $FILE*
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_group_ownership_var_log_audit'

# ── FIXING: File Groupownership Audit Configuration ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupownership_audit_configuration
# BEGIN fix (326 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupownership_audit_configuration'
###############################################################################
(>&2 echo "Remediating rule 326/379: 'xccdf_org.ssgproject.content_rule_file_groupownership_audit_configuration'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

find -L /etc/audit/ -maxdepth 1 -type f ! -group 0 -regextype posix-extended -regex '^.*audit(\.rules|d\.conf)$' -exec chgrp -L 0 {} \;

find -L /etc/audit/rules.d/ -maxdepth 1 -type f ! -group 0 -regextype posix-extended -regex '^.*\.rules$' -exec chgrp -L 0 {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupownership_audit_configuration'

# ── FIXING: File Ownership Audit Configuration ──
# Rule: xccdf_org.ssgproject.content_rule_file_ownership_audit_configuration
# BEGIN fix (327 / 379) for 'xccdf_org.ssgproject.content_rule_file_ownership_audit_configuration'
###############################################################################
(>&2 echo "Remediating rule 327/379: 'xccdf_org.ssgproject.content_rule_file_ownership_audit_configuration'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

find -L /etc/audit/ -maxdepth 1 -type f ! -uid 0 -regextype posix-extended -regex '^.*audit(\.rules|d\.conf)$' -exec chown -L 0 {} \;

find -L /etc/audit/rules.d/ -maxdepth 1 -type f ! -uid 0 -regextype posix-extended -regex '^.*\.rules$' -exec chown -L 0 {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_ownership_audit_configuration'

# ── FIXING: File Ownership Var Log Audit Stig ──
# Rule: xccdf_org.ssgproject.content_rule_file_ownership_var_log_audit_stig
# BEGIN fix (328 / 379) for 'xccdf_org.ssgproject.content_rule_file_ownership_var_log_audit_stig'
###############################################################################
(>&2 echo "Remediating rule 328/379: 'xccdf_org.ssgproject.content_rule_file_ownership_var_log_audit_stig'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

if LC_ALL=C grep -iw log_file /etc/audit/auditd.conf; then
    FILE=$(awk -F "=" '/^log_file/ {print $2}' /etc/audit/auditd.conf | tr -d ' ')
    chown root $FILE*
else
    chown root /var/log/audit/audit.log*
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_ownership_var_log_audit_stig'

# ── FIXING: File Permissions Audit Configuration ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_audit_configuration
# BEGIN fix (329 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_audit_configuration'
###############################################################################
(>&2 echo "Remediating rule 329/379: 'xccdf_org.ssgproject.content_rule_file_permissions_audit_configuration'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

find -L /etc/audit/ -maxdepth 1 -perm /u+xs,g+xws,o+xwrt  -type f -regextype posix-extended -regex '^.*audit(\.rules|d\.conf)$' -exec chmod u-xs,g-xws,o-xwrt {} \;

find -L /etc/audit/rules.d/ -maxdepth 1 -perm /u+xs,g+xws,o+xwrt  -type f -regextype posix-extended -regex '^.*\.rules$' -exec chmod u-xs,g-xws,o-xwrt {} \;

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_audit_configuration'

# ── FIXING: File Permissions Var Log Audit ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_var_log_audit
# BEGIN fix (330 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_var_log_audit'
###############################################################################
(>&2 echo "Remediating rule 330/379: 'xccdf_org.ssgproject.content_rule_file_permissions_var_log_audit'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q audit && rpm --quiet -q kernel; then

if LC_ALL=C grep -iw ^log_file /etc/audit/auditd.conf; then
    FILE=$(awk -F "=" '/^log_file/ {print $2}' /etc/audit/auditd.conf | tr -d ' ')
else
    FILE="/var/log/audit/audit.log"
fi


chmod 0600 $FILE

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_var_log_audit'

# ── FIXING: File Groupownership Audit Binaries ──
# Rule: xccdf_org.ssgproject.content_rule_file_groupownership_audit_binaries
# BEGIN fix (377 / 379) for 'xccdf_org.ssgproject.content_rule_file_groupownership_audit_binaries'
###############################################################################
(>&2 echo "Remediating rule 377/379: 'xccdf_org.ssgproject.content_rule_file_groupownership_audit_binaries'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

chgrp 0 /sbin/auditctl
chgrp 0 /sbin/aureport
chgrp 0 /sbin/ausearch
chgrp 0 /sbin/autrace
chgrp 0 /sbin/auditd
chgrp 0 /sbin/augenrules

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_groupownership_audit_binaries'

# ── FIXING: File Ownership Audit Binaries ──
# Rule: xccdf_org.ssgproject.content_rule_file_ownership_audit_binaries
# BEGIN fix (378 / 379) for 'xccdf_org.ssgproject.content_rule_file_ownership_audit_binaries'
###############################################################################
(>&2 echo "Remediating rule 378/379: 'xccdf_org.ssgproject.content_rule_file_ownership_audit_binaries'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

chown 0 /sbin/auditctl
chown 0 /sbin/aureport
chown 0 /sbin/ausearch
chown 0 /sbin/autrace
chown 0 /sbin/auditd
chown 0 /sbin/augenrules

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_ownership_audit_binaries'

# ── FIXING: File Permissions Audit Binaries ──
# Rule: xccdf_org.ssgproject.content_rule_file_permissions_audit_binaries
# BEGIN fix (379 / 379) for 'xccdf_org.ssgproject.content_rule_file_permissions_audit_binaries'
###############################################################################
(>&2 echo "Remediating rule 379/379: 'xccdf_org.ssgproject.content_rule_file_permissions_audit_binaries'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

chmod u-s,g-ws,o-wt /sbin/auditctl

chmod u-s,g-ws,o-wt /sbin/aureport

chmod u-s,g-ws,o-wt /sbin/ausearch

chmod u-s,g-ws,o-wt /sbin/autrace

chmod u-s,g-ws,o-wt /sbin/auditd

chmod u-s,g-ws,o-wt /sbin/augenrules

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_file_permissions_audit_binaries'
