#!/bin/bash
#
# RHEL 9 OSCAP Remediation - User Accounts & Password Policy
# Description: Password aging, complexity (PAM pwquality/faillock), account lockout, umask, shell timeouts, sudo hardening, root account, UID/GID uniqueness, etc.
# Rules covered: 57
#
# Usage: Run as root: bash 07_user_accounts_and_password_policy.sh
#

set -o nounset


# ── FIXING: Sudo Add Use Pty ──
# Rule: xccdf_org.ssgproject.content_rule_sudo_add_use_pty
# BEGIN fix (25 / 379) for 'xccdf_org.ssgproject.content_rule_sudo_add_use_pty'
###############################################################################
(>&2 echo "Remediating rule 25/379: 'xccdf_org.ssgproject.content_rule_sudo_add_use_pty'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q sudo; then

if /usr/sbin/visudo -qcf /etc/sudoers; then
    cp /etc/sudoers /etc/sudoers.bak
    if ! grep -P '^[\s]*Defaults[\s]*\buse_pty\b.*$' /etc/sudoers; then
        # sudoers file doesn't define Option use_pty
        echo "Defaults use_pty" >> /etc/sudoers
    fi
    
    # Check validity of sudoers and cleanup bak
    if /usr/sbin/visudo -qcf /etc/sudoers; then
        rm -f /etc/sudoers.bak
    else
        echo "Fail to validate remediated /etc/sudoers, reverting to original file."
        mv /etc/sudoers.bak /etc/sudoers
        false
    fi
else
    echo "Skipping remediation, /etc/sudoers failed to validate"
    false
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sudo_add_use_pty'

# ── FIXING: Sudo Custom Logfile ──
# Rule: xccdf_org.ssgproject.content_rule_sudo_custom_logfile
# BEGIN fix (26 / 379) for 'xccdf_org.ssgproject.content_rule_sudo_custom_logfile'
###############################################################################
(>&2 echo "Remediating rule 26/379: 'xccdf_org.ssgproject.content_rule_sudo_custom_logfile'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q sudo; then

var_sudo_logfile='/var/log/sudo.log'


if /usr/sbin/visudo -qcf /etc/sudoers; then
    cp /etc/sudoers /etc/sudoers.bak
    if ! grep -P '^[\s]*Defaults[\s]*\blogfile\s*=\s*(?:"?([^",\s]+)"?)\b.*$' /etc/sudoers; then
        # sudoers file doesn't define Option logfile
        echo "Defaults logfile=${var_sudo_logfile}" >> /etc/sudoers
    else
        # sudoers file defines Option logfile, remediate if appropriate value is not set
        if ! grep -P "^[\s]*Defaults.*\blogfile=${var_sudo_logfile}\b.*$" /etc/sudoers; then
            
            escaped_variable=${var_sudo_logfile//$'/'/$'\/'}
            sed -Ei "s/(^[\s]*Defaults.*\blogfile=)[-]?.+(\b.*$)/\1$escaped_variable\2/" /etc/sudoers
        fi
    fi
    
    # Check validity of sudoers and cleanup bak
    if /usr/sbin/visudo -qcf /etc/sudoers; then
        rm -f /etc/sudoers.bak
    else
        echo "Fail to validate remediated /etc/sudoers, reverting to original file."
        mv /etc/sudoers.bak /etc/sudoers
        false
    fi
else
    echo "Skipping remediation, /etc/sudoers failed to validate"
    false
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sudo_custom_logfile'

# ── FIXING: Sudo Require Authentication ──
# Rule: xccdf_org.ssgproject.content_rule_sudo_require_authentication
# BEGIN fix (27 / 379) for 'xccdf_org.ssgproject.content_rule_sudo_require_authentication'
###############################################################################
(>&2 echo "Remediating rule 27/379: 'xccdf_org.ssgproject.content_rule_sudo_require_authentication'"); (

for f in /etc/sudoers /etc/sudoers.d/* ; do
  if [ ! -e "$f" ] ; then
    continue
  fi
  matching_list=$(grep -P '^(?!#).*[\s]+NOPASSWD[\s]*\:.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      # comment out "NOPASSWD" matches to preserve user data
      sed -i "s/^${entry}$/# &/g" $f
    done <<< "$matching_list"

    /usr/sbin/visudo -cf $f &> /dev/null || echo "Fail to validate $f with visudo"
  fi
done

for f in /etc/sudoers /etc/sudoers.d/* ; do
  if [ ! -e "$f" ] ; then
    continue
  fi
  matching_list=$(grep -P '^(?!#).*[\s]+\!authenticate.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      # comment out "!authenticate" matches to preserve user data
      sed -i "s/^${entry}$/# &/g" $f
    done <<< "$matching_list"

    /usr/sbin/visudo -cf $f &> /dev/null || echo "Fail to validate $f with visudo"
  fi
done

) # END fix for 'xccdf_org.ssgproject.content_rule_sudo_require_authentication'

# ── FIXING: Sudo Require Reauthentication ──
# Rule: xccdf_org.ssgproject.content_rule_sudo_require_reauthentication
# BEGIN fix (28 / 379) for 'xccdf_org.ssgproject.content_rule_sudo_require_reauthentication'
###############################################################################
(>&2 echo "Remediating rule 28/379: 'xccdf_org.ssgproject.content_rule_sudo_require_reauthentication'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q sudo; then

var_sudo_timestamp_timeout='5'


if grep -Px '^[\s]*Defaults.*timestamp_timeout[\s]*=.*' /etc/sudoers.d/*; then
    find /etc/sudoers.d/ -type f -exec sed -Ei "/^[[:blank:]]*Defaults.*timestamp_timeout[[:blank:]]*=.*/d" {} \;
fi

if /usr/sbin/visudo -qcf /etc/sudoers; then
    cp /etc/sudoers /etc/sudoers.bak
    if ! grep -P '^[\s]*Defaults.*timestamp_timeout[\s]*=[\s]*[-]?\w+.*$' /etc/sudoers; then
        # sudoers file doesn't define Option timestamp_timeout
        echo "Defaults timestamp_timeout=${var_sudo_timestamp_timeout}" >> /etc/sudoers
    else
        # sudoers file defines Option timestamp_timeout, remediate wrong values if present
        if grep -qP "^[\s]*Defaults\s.*\btimestamp_timeout[\s]*=[\s]*(?!${var_sudo_timestamp_timeout}\b)[-]?\w+\b.*$" /etc/sudoers; then
            sed -Ei "s/(^[[:blank:]]*Defaults.*timestamp_timeout[[:blank:]]*=)[[:blank:]]*[-]?\w+(.*$)/\1${var_sudo_timestamp_timeout}\2/" /etc/sudoers
        fi
    fi
    
    # Check validity of sudoers and cleanup bak
    if /usr/sbin/visudo -qcf /etc/sudoers; then
        rm -f /etc/sudoers.bak
    else
        echo "Fail to validate remediated /etc/sudoers, reverting to original file."
        mv /etc/sudoers.bak /etc/sudoers
        false
    fi
else
    echo "Skipping remediation, /etc/sudoers failed to validate"
    false
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sudo_require_reauthentication'

# ── FIXING: Enable Authselect ──
# Rule: xccdf_org.ssgproject.content_rule_enable_authselect
# BEGIN fix (30 / 379) for 'xccdf_org.ssgproject.content_rule_enable_authselect'
###############################################################################
(>&2 echo "Remediating rule 30/379: 'xccdf_org.ssgproject.content_rule_enable_authselect'"); (

var_authselect_profile='sssd'


authselect current

if test "$?" -ne 0; then
    authselect select "$var_authselect_profile"

    if test "$?" -ne 0; then
        if rpm --quiet --verify pam; then
            authselect select --force "$var_authselect_profile"
        else
	        echo "authselect is not used but files from the 'pam' package have been altered, so the authselect configuration won't be forced." >&2
        fi
    fi
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_enable_authselect'

# ── FIXING: Account Password Pam Faillock Password Auth ──
# Rule: xccdf_org.ssgproject.content_rule_account_password_pam_faillock_password_auth
# BEGIN fix (46 / 379) for 'xccdf_org.ssgproject.content_rule_account_password_pam_faillock_password_auth'
###############################################################################
(>&2 echo "Remediating rule 46/379: 'xccdf_org.ssgproject.content_rule_account_password_pam_faillock_password_auth'"); (

if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock

authselect apply-changes -b
else
    
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
for pam_file in "${AUTH_FILES[@]}"
do
    if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
        sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
        sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
        sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
    fi
    sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
done

fi

) # END fix for 'xccdf_org.ssgproject.content_rule_account_password_pam_faillock_password_auth'

# ── FIXING: Account Password Pam Faillock System Auth ──
# Rule: xccdf_org.ssgproject.content_rule_account_password_pam_faillock_system_auth
# BEGIN fix (47 / 379) for 'xccdf_org.ssgproject.content_rule_account_password_pam_faillock_system_auth'
###############################################################################
(>&2 echo "Remediating rule 47/379: 'xccdf_org.ssgproject.content_rule_account_password_pam_faillock_system_auth'"); (

if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock

authselect apply-changes -b
else
    
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
for pam_file in "${AUTH_FILES[@]}"
do
    if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
        sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
        sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
        sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
    fi
    sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
done

fi

) # END fix for 'xccdf_org.ssgproject.content_rule_account_password_pam_faillock_system_auth'

# ── FIXING: Accounts Password Pam Pwhistory Remember Password Auth ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_password_pam_pwhistory_remember_password_auth
# BEGIN fix (48 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_pwhistory_remember_password_auth'
###############################################################################
(>&2 echo "Remediating rule 48/379: 'xccdf_org.ssgproject.content_rule_accounts_password_pam_pwhistory_remember_password_auth'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_remember='24'
var_password_pam_remember_control_flag='requisite,required'


var_password_pam_remember_control_flag="$(echo $var_password_pam_remember_control_flag | cut -d \, -f 1)"

if [ -f /usr/bin/authselect ]; then
    if authselect list-features sssd | grep -q with-pwhistory; then
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi
        authselect enable-feature with-pwhistory

        authselect apply-changes -b
    else
        
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi

        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        # If not already in use, a custom profile is created preserving the enabled features.
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            # The "local" profile does not contain essential security features required by multiple Benchmarks.
            # If currently used, it is replaced by "sssd", which is the best option in this case.
            if [[ $CURRENT_PROFILE == local ]]; then
                CURRENT_PROFILE="sssd"
            fi
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"
            
            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done
            
            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "/etc/pam.d/password-auth")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

        authselect apply-changes -b
        
        if ! grep -qP "^\s*password\s+\$var_password_pam_remember_control_flag\s+pam_pwhistory.so\s*.*" "$PAM_FILE_PATH"; then
            # Line matching group + control + module was not found. Check group + module.
            if [ "$(grep -cP '^\s*password\s+.*\s+pam_pwhistory.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
                # The control is updated only if one single line matches.
                sed -i -E --follow-symlinks "s/^(\s*password\s+).*(\bpam_pwhistory.so.*)/\1$var_password_pam_remember_control_flag \2/" "$PAM_FILE_PATH"
            else
                LAST_MATCH_LINE=$(grep -nP "^password.*requisite.*pam_pwquality\.so" "$PAM_FILE_PATH" | tail -n 1 | cut -d: -f 1)
                if [ ! -z $LAST_MATCH_LINE ]; then
                    sed -i --follow-symlinks $LAST_MATCH_LINE" a password     $var_password_pam_remember_control_flag    pam_pwhistory.so" "$PAM_FILE_PATH"
                else
                    echo "password    $var_password_pam_remember_control_flag    pam_pwhistory.so" >> "$PAM_FILE_PATH"
                fi
            fi
        fi
    fi
else

    
    if ! grep -qP "^\s*password\s+\$var_password_pam_remember_control_flag\s+pam_pwhistory.so\s*.*" "/etc/pam.d/password-auth"; then
        # Line matching group + control + module was not found. Check group + module.
        if [ "$(grep -cP '^\s*password\s+.*\s+pam_pwhistory.so\s*' "/etc/pam.d/password-auth")" -eq 1 ]; then
            # The control is updated only if one single line matches.
            sed -i -E --follow-symlinks "s/^(\s*password\s+).*(\bpam_pwhistory.so.*)/\1$var_password_pam_remember_control_flag \2/" "/etc/pam.d/password-auth"
        else
            LAST_MATCH_LINE=$(grep -nP "^password.*requisite.*pam_pwquality\.so" "/etc/pam.d/password-auth" | tail -n 1 | cut -d: -f 1)
            if [ ! -z $LAST_MATCH_LINE ]; then
                sed -i --follow-symlinks $LAST_MATCH_LINE" a password     $var_password_pam_remember_control_flag    pam_pwhistory.so" "/etc/pam.d/password-auth"
            else
                echo "password    $var_password_pam_remember_control_flag    pam_pwhistory.so" >> "/etc/pam.d/password-auth"
            fi
        fi
    fi

fi

PWHISTORY_CONF="/etc/security/pwhistory.conf"
if [ -f $PWHISTORY_CONF ]; then
    regex="^\s*remember\s*="
    line="remember = $var_password_pam_remember"
    if ! grep -q $regex $PWHISTORY_CONF; then
        echo $line >> $PWHISTORY_CONF
    else
        sed -i --follow-symlinks 's|^\s*\(remember\s*=\s*\)\(\S\+\)|\1'"$var_password_pam_remember"'|g' $PWHISTORY_CONF
    fi
    if [ -e "/etc/pam.d/password-auth" ] ; then
        PAM_FILE_PATH="/etc/pam.d/password-auth"
        if [ -f /usr/bin/authselect ]; then
            
            if ! authselect check; then
            echo "
            authselect integrity check failed. Remediation aborted!
            This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
            It is not recommended to manually edit the PAM files when authselect tool is available.
            In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
            exit 1
            fi

            CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
            # If not already in use, a custom profile is created preserving the enabled features.
            if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                # The "local" profile does not contain essential security features required by multiple Benchmarks.
                # If currently used, it is replaced by "sssd", which is the best option in this case.
                if [[ $CURRENT_PROFILE == local ]]; then
                    CURRENT_PROFILE="sssd"
                fi
                authselect create-profile hardening -b $CURRENT_PROFILE
                CURRENT_PROFILE="custom/hardening"
                
                authselect apply-changes -b --backup=before-hardening-custom-profile
                authselect select $CURRENT_PROFILE
                for feature in $ENABLED_FEATURES; do
                    authselect enable-feature $feature;
                done
                
                authselect apply-changes -b --backup=after-hardening-custom-profile
            fi
            PAM_FILE_NAME=$(basename "/etc/pam.d/password-auth")
            PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

            authselect apply-changes -b
        fi
        
    if grep -qP "^\s*password\s.*\bpam_pwhistory.so\s.*\bremember\b" "$PAM_FILE_PATH"; then
        sed -i -E --follow-symlinks "s/(.*password.*pam_pwhistory.so.*)\bremember\b=?[[:alnum:]]*(.*)/\1\2/g" "$PAM_FILE_PATH"
    fi
        if [ -f /usr/bin/authselect ]; then
            
            authselect apply-changes -b
        fi
    else
        echo "/etc/pam.d/password-auth was not found" >&2
    fi
else
    PAM_FILE_PATH="/etc/pam.d/password-auth"
    if [ -f /usr/bin/authselect ]; then
        
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi

        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        # If not already in use, a custom profile is created preserving the enabled features.
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            # The "local" profile does not contain essential security features required by multiple Benchmarks.
            # If currently used, it is replaced by "sssd", which is the best option in this case.
            if [[ $CURRENT_PROFILE == local ]]; then
                CURRENT_PROFILE="sssd"
            fi
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"
            
            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done
            
            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "/etc/pam.d/password-auth")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

        authselect apply-changes -b
    fi
    

    if ! grep -qP "^\s*password\s+requisite\s+pam_pwhistory.so\s*.*" "$PAM_FILE_PATH"; then
        # Line matching group + control + module was not found. Check group + module.
        if [ "$(grep -cP '^\s*password\s+.*\s+pam_pwhistory.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
            # The control is updated only if one single line matches.
            sed -i -E --follow-symlinks "s/^(\s*password\s+).*(\bpam_pwhistory.so.*)/\1requisite \2/" "$PAM_FILE_PATH"
        else
            echo "password    requisite    pam_pwhistory.so" >> "$PAM_FILE_PATH"
        fi
    fi
    # Check the option
    if ! grep -qP "^\s*password\s+requisite\s+pam_pwhistory.so\s*.*\sremember\b" "$PAM_FILE_PATH"; then
        sed -i -E --follow-symlinks "/\s*password\s+requisite\s+pam_pwhistory.so.*/ s/$/ remember=$var_password_pam_remember/" "$PAM_FILE_PATH"
    else
        sed -i -E --follow-symlinks "s/(\s*password\s+requisite\s+pam_pwhistory.so\s+.*)(remember=)[[:alnum:]]+\s*(.*)/\1\2$var_password_pam_remember \3/" "$PAM_FILE_PATH"
    fi
    if [ -f /usr/bin/authselect ]; then
        
        authselect apply-changes -b
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_pwhistory_remember_password_auth'

# ── FIXING: Accounts Password Pam Pwhistory Remember System Auth ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_password_pam_pwhistory_remember_system_auth
# BEGIN fix (49 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_pwhistory_remember_system_auth'
###############################################################################
(>&2 echo "Remediating rule 49/379: 'xccdf_org.ssgproject.content_rule_accounts_password_pam_pwhistory_remember_system_auth'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_remember='24'
var_password_pam_remember_control_flag='requisite,required'


var_password_pam_remember_control_flag="$(echo $var_password_pam_remember_control_flag | cut -d \, -f 1)"

if [ -f /usr/bin/authselect ]; then
    if authselect list-features sssd | grep -q with-pwhistory; then
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi
        authselect enable-feature with-pwhistory

        authselect apply-changes -b
    else
        
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi

        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        # If not already in use, a custom profile is created preserving the enabled features.
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            # The "local" profile does not contain essential security features required by multiple Benchmarks.
            # If currently used, it is replaced by "sssd", which is the best option in this case.
            if [[ $CURRENT_PROFILE == local ]]; then
                CURRENT_PROFILE="sssd"
            fi
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"
            
            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done
            
            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "/etc/pam.d/system-auth")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

        authselect apply-changes -b
        
        if ! grep -qP "^\s*password\s+\$var_password_pam_remember_control_flag\s+pam_pwhistory.so\s*.*" "$PAM_FILE_PATH"; then
            # Line matching group + control + module was not found. Check group + module.
            if [ "$(grep -cP '^\s*password\s+.*\s+pam_pwhistory.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
                # The control is updated only if one single line matches.
                sed -i -E --follow-symlinks "s/^(\s*password\s+).*(\bpam_pwhistory.so.*)/\1$var_password_pam_remember_control_flag \2/" "$PAM_FILE_PATH"
            else
                LAST_MATCH_LINE=$(grep -nP "^password.*requisite.*pam_pwquality\.so" "$PAM_FILE_PATH" | tail -n 1 | cut -d: -f 1)
                if [ ! -z $LAST_MATCH_LINE ]; then
                    sed -i --follow-symlinks $LAST_MATCH_LINE" a password     $var_password_pam_remember_control_flag    pam_pwhistory.so" "$PAM_FILE_PATH"
                else
                    echo "password    $var_password_pam_remember_control_flag    pam_pwhistory.so" >> "$PAM_FILE_PATH"
                fi
            fi
        fi
    fi
else

    
    if ! grep -qP "^\s*password\s+\$var_password_pam_remember_control_flag\s+pam_pwhistory.so\s*.*" "/etc/pam.d/system-auth"; then
        # Line matching group + control + module was not found. Check group + module.
        if [ "$(grep -cP '^\s*password\s+.*\s+pam_pwhistory.so\s*' "/etc/pam.d/system-auth")" -eq 1 ]; then
            # The control is updated only if one single line matches.
            sed -i -E --follow-symlinks "s/^(\s*password\s+).*(\bpam_pwhistory.so.*)/\1$var_password_pam_remember_control_flag \2/" "/etc/pam.d/system-auth"
        else
            LAST_MATCH_LINE=$(grep -nP "^password.*requisite.*pam_pwquality\.so" "/etc/pam.d/system-auth" | tail -n 1 | cut -d: -f 1)
            if [ ! -z $LAST_MATCH_LINE ]; then
                sed -i --follow-symlinks $LAST_MATCH_LINE" a password     $var_password_pam_remember_control_flag    pam_pwhistory.so" "/etc/pam.d/system-auth"
            else
                echo "password    $var_password_pam_remember_control_flag    pam_pwhistory.so" >> "/etc/pam.d/system-auth"
            fi
        fi
    fi

fi

PWHISTORY_CONF="/etc/security/pwhistory.conf"
if [ -f $PWHISTORY_CONF ]; then
    regex="^\s*remember\s*="
    line="remember = $var_password_pam_remember"
    if ! grep -q $regex $PWHISTORY_CONF; then
        echo $line >> $PWHISTORY_CONF
    else
        sed -i --follow-symlinks 's|^\s*\(remember\s*=\s*\)\(\S\+\)|\1'"$var_password_pam_remember"'|g' $PWHISTORY_CONF
    fi
    if [ -e "/etc/pam.d/system-auth" ] ; then
        PAM_FILE_PATH="/etc/pam.d/system-auth"
        if [ -f /usr/bin/authselect ]; then
            
            if ! authselect check; then
            echo "
            authselect integrity check failed. Remediation aborted!
            This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
            It is not recommended to manually edit the PAM files when authselect tool is available.
            In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
            exit 1
            fi

            CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
            # If not already in use, a custom profile is created preserving the enabled features.
            if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                # The "local" profile does not contain essential security features required by multiple Benchmarks.
                # If currently used, it is replaced by "sssd", which is the best option in this case.
                if [[ $CURRENT_PROFILE == local ]]; then
                    CURRENT_PROFILE="sssd"
                fi
                authselect create-profile hardening -b $CURRENT_PROFILE
                CURRENT_PROFILE="custom/hardening"
                
                authselect apply-changes -b --backup=before-hardening-custom-profile
                authselect select $CURRENT_PROFILE
                for feature in $ENABLED_FEATURES; do
                    authselect enable-feature $feature;
                done
                
                authselect apply-changes -b --backup=after-hardening-custom-profile
            fi
            PAM_FILE_NAME=$(basename "/etc/pam.d/system-auth")
            PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

            authselect apply-changes -b
        fi
        
    if grep -qP "^\s*password\s.*\bpam_pwhistory.so\s.*\bremember\b" "$PAM_FILE_PATH"; then
        sed -i -E --follow-symlinks "s/(.*password.*pam_pwhistory.so.*)\bremember\b=?[[:alnum:]]*(.*)/\1\2/g" "$PAM_FILE_PATH"
    fi
        if [ -f /usr/bin/authselect ]; then
            
            authselect apply-changes -b
        fi
    else
        echo "/etc/pam.d/system-auth was not found" >&2
    fi
else
    PAM_FILE_PATH="/etc/pam.d/system-auth"
    if [ -f /usr/bin/authselect ]; then
        
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi

        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        # If not already in use, a custom profile is created preserving the enabled features.
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            # The "local" profile does not contain essential security features required by multiple Benchmarks.
            # If currently used, it is replaced by "sssd", which is the best option in this case.
            if [[ $CURRENT_PROFILE == local ]]; then
                CURRENT_PROFILE="sssd"
            fi
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"
            
            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done
            
            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "/etc/pam.d/system-auth")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

        authselect apply-changes -b
    fi
    

    if ! grep -qP "^\s*password\s+requisite\s+pam_pwhistory.so\s*.*" "$PAM_FILE_PATH"; then
        # Line matching group + control + module was not found. Check group + module.
        if [ "$(grep -cP '^\s*password\s+.*\s+pam_pwhistory.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
            # The control is updated only if one single line matches.
            sed -i -E --follow-symlinks "s/^(\s*password\s+).*(\bpam_pwhistory.so.*)/\1requisite \2/" "$PAM_FILE_PATH"
        else
            echo "password    requisite    pam_pwhistory.so" >> "$PAM_FILE_PATH"
        fi
    fi
    # Check the option
    if ! grep -qP "^\s*password\s+requisite\s+pam_pwhistory.so\s*.*\sremember\b" "$PAM_FILE_PATH"; then
        sed -i -E --follow-symlinks "/\s*password\s+requisite\s+pam_pwhistory.so.*/ s/$/ remember=$var_password_pam_remember/" "$PAM_FILE_PATH"
    else
        sed -i -E --follow-symlinks "s/(\s*password\s+requisite\s+pam_pwhistory.so\s+.*)(remember=)[[:alnum:]]+\s*(.*)/\1\2$var_password_pam_remember \3/" "$PAM_FILE_PATH"
    fi
    if [ -f /usr/bin/authselect ]; then
        
        authselect apply-changes -b
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_pwhistory_remember_system_auth'

# ── FIXING: Accounts Passwords Pam Faillock Deny ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny
# BEGIN fix (50 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny'
###############################################################################
(>&2 echo "Remediating rule 50/379: 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_accounts_passwords_pam_faillock_deny='5'


if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock

authselect apply-changes -b
else
    
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
for pam_file in "${AUTH_FILES[@]}"
do
    if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
        sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
        sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
        sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
    fi
    sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
done

fi

AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
SKIP_FAILLOCK_CHECK=false

FAILLOCK_CONF="/etc/security/faillock.conf"
if [ -f $FAILLOCK_CONF ] || [ "$SKIP_FAILLOCK_CHECK" = "true" ]; then
    regex="^\s*deny\s*="
    line="deny = $var_accounts_passwords_pam_faillock_deny"
    if ! grep -q $regex $FAILLOCK_CONF; then
        echo $line >> $FAILLOCK_CONF
    else
        sed -i --follow-symlinks 's|^\s*\(deny\s*=\s*\)\(\S\+\)|\1'"$var_accounts_passwords_pam_faillock_deny"'|g' $FAILLOCK_CONF
    fi
    
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -e "$pam_file" ] ; then
            PAM_FILE_PATH="$pam_file"
            if [ -f /usr/bin/authselect ]; then
                
                if ! authselect check; then
                echo "
                authselect integrity check failed. Remediation aborted!
                This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
                It is not recommended to manually edit the PAM files when authselect tool is available.
                In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
                exit 1
                fi

                CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
                # If not already in use, a custom profile is created preserving the enabled features.
                if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                    ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                    # The "local" profile does not contain essential security features required by multiple Benchmarks.
                    # If currently used, it is replaced by "sssd", which is the best option in this case.
                    if [[ $CURRENT_PROFILE == local ]]; then
                        CURRENT_PROFILE="sssd"
                    fi
                    authselect create-profile hardening -b $CURRENT_PROFILE
                    CURRENT_PROFILE="custom/hardening"
                    
                    authselect apply-changes -b --backup=before-hardening-custom-profile
                    authselect select $CURRENT_PROFILE
                    for feature in $ENABLED_FEATURES; do
                        authselect enable-feature $feature;
                    done
                    
                    authselect apply-changes -b --backup=after-hardening-custom-profile
                fi
                PAM_FILE_NAME=$(basename "$pam_file")
                PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

                authselect apply-changes -b
            fi
            
        if grep -qP "^\s*auth\s.*\bpam_faillock.so\s.*\bdeny\b" "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks "s/(.*auth.*pam_faillock.so.*)\bdeny\b=?[[:alnum:]]*(.*)/\1\2/g" "$PAM_FILE_PATH"
        fi
            if [ -f /usr/bin/authselect ]; then
                
                authselect apply-changes -b
            fi
        else
            echo "$pam_file was not found" >&2
        fi
    done
    
else
    for pam_file in "${AUTH_FILES[@]}"
    do
        if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*deny' "$pam_file"; then
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ deny='"$var_accounts_passwords_pam_faillock_deny"'/' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ deny='"$var_accounts_passwords_pam_faillock_deny"'/' "$pam_file"
        else
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*preauth.*silent.*\)\('"deny"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_deny"'\3/' "$pam_file"
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*authfail.*\)\('"deny"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_deny"'\3/' "$pam_file"
        fi
    done
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny'

# ── FIXING: Accounts Passwords Pam Faillock Deny Root ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny_root
# BEGIN fix (51 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny_root'
###############################################################################
(>&2 echo "Remediating rule 51/379: 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny_root'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock

authselect apply-changes -b
else
    
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
for pam_file in "${AUTH_FILES[@]}"
do
    if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
        sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
        sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
        sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
    fi
    sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
done

fi

AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
SKIP_FAILLOCK_CHECK=false

FAILLOCK_CONF="/etc/security/faillock.conf"
if [ -f $FAILLOCK_CONF ] || [ "$SKIP_FAILLOCK_CHECK" = "true" ]; then
    regex="^\s*even_deny_root"
    line="even_deny_root"
    if ! grep -q $regex $FAILLOCK_CONF; then
        echo $line >> $FAILLOCK_CONF
    fi
    
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -e "$pam_file" ] ; then
            PAM_FILE_PATH="$pam_file"
            if [ -f /usr/bin/authselect ]; then
                
                if ! authselect check; then
                echo "
                authselect integrity check failed. Remediation aborted!
                This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
                It is not recommended to manually edit the PAM files when authselect tool is available.
                In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
                exit 1
                fi

                CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
                # If not already in use, a custom profile is created preserving the enabled features.
                if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                    ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                    # The "local" profile does not contain essential security features required by multiple Benchmarks.
                    # If currently used, it is replaced by "sssd", which is the best option in this case.
                    if [[ $CURRENT_PROFILE == local ]]; then
                        CURRENT_PROFILE="sssd"
                    fi
                    authselect create-profile hardening -b $CURRENT_PROFILE
                    CURRENT_PROFILE="custom/hardening"
                    
                    authselect apply-changes -b --backup=before-hardening-custom-profile
                    authselect select $CURRENT_PROFILE
                    for feature in $ENABLED_FEATURES; do
                        authselect enable-feature $feature;
                    done
                    
                    authselect apply-changes -b --backup=after-hardening-custom-profile
                fi
                PAM_FILE_NAME=$(basename "$pam_file")
                PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

                authselect apply-changes -b
            fi
            
        if grep -qP "^\s*auth\s.*\bpam_faillock.so\s.*\beven_deny_root\b" "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks "s/(.*auth.*pam_faillock.so.*)\beven_deny_root\b=?[[:alnum:]]*(.*)/\1\2/g" "$PAM_FILE_PATH"
        fi
            if [ -f /usr/bin/authselect ]; then
                
                authselect apply-changes -b
            fi
        else
            echo "$pam_file was not found" >&2
        fi
    done
    
else
    for pam_file in "${AUTH_FILES[@]}"
    do
        if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*even_deny_root' "$pam_file"; then
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ even_deny_root/' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ even_deny_root/' "$pam_file"
        fi
    done
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_deny_root'

# ── FIXING: Accounts Passwords Pam Faillock Unlock Time ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_unlock_time
# BEGIN fix (52 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_unlock_time'
###############################################################################
(>&2 echo "Remediating rule 52/379: 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_unlock_time'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_accounts_passwords_pam_faillock_unlock_time='900'


if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature with-faillock

authselect apply-changes -b
else
    
AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
for pam_file in "${AUTH_FILES[@]}"
do
    if ! grep -qE '^\s*auth\s+required\s+pam_faillock\.so\s+(preauth silent|authfail).*$' "$pam_file" ; then
        sed -i --follow-symlinks '/^auth.*sufficient.*pam_unix\.so.*/i auth        required      pam_faillock.so preauth silent' "$pam_file"
        sed -i --follow-symlinks '/^auth.*required.*pam_deny\.so.*/i auth        required      pam_faillock.so authfail' "$pam_file"
        sed -i --follow-symlinks '/^account.*required.*pam_unix\.so.*/i account     required      pam_faillock.so' "$pam_file"
    fi
    sed -Ei 's/(auth.*)(\[default=die\])(.*pam_faillock\.so)/\1required     \3/g' "$pam_file"
done

fi

AUTH_FILES=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")
SKIP_FAILLOCK_CHECK=false

FAILLOCK_CONF="/etc/security/faillock.conf"
if [ -f $FAILLOCK_CONF ] || [ "$SKIP_FAILLOCK_CHECK" = "true" ]; then
    regex="^\s*unlock_time\s*="
    line="unlock_time = $var_accounts_passwords_pam_faillock_unlock_time"
    if ! grep -q $regex $FAILLOCK_CONF; then
        echo $line >> $FAILLOCK_CONF
    else
        sed -i --follow-symlinks 's|^\s*\(unlock_time\s*=\s*\)\(\S\+\)|\1'"$var_accounts_passwords_pam_faillock_unlock_time"'|g' $FAILLOCK_CONF
    fi
    
    for pam_file in "${AUTH_FILES[@]}"
    do
        if [ -e "$pam_file" ] ; then
            PAM_FILE_PATH="$pam_file"
            if [ -f /usr/bin/authselect ]; then
                
                if ! authselect check; then
                echo "
                authselect integrity check failed. Remediation aborted!
                This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
                It is not recommended to manually edit the PAM files when authselect tool is available.
                In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
                exit 1
                fi

                CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
                # If not already in use, a custom profile is created preserving the enabled features.
                if [[ ! $CURRENT_PROFILE == custom/* ]]; then
                    ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
                    # The "local" profile does not contain essential security features required by multiple Benchmarks.
                    # If currently used, it is replaced by "sssd", which is the best option in this case.
                    if [[ $CURRENT_PROFILE == local ]]; then
                        CURRENT_PROFILE="sssd"
                    fi
                    authselect create-profile hardening -b $CURRENT_PROFILE
                    CURRENT_PROFILE="custom/hardening"
                    
                    authselect apply-changes -b --backup=before-hardening-custom-profile
                    authselect select $CURRENT_PROFILE
                    for feature in $ENABLED_FEATURES; do
                        authselect enable-feature $feature;
                    done
                    
                    authselect apply-changes -b --backup=after-hardening-custom-profile
                fi
                PAM_FILE_NAME=$(basename "$pam_file")
                PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

                authselect apply-changes -b
            fi
            
        if grep -qP "^\s*auth\s.*\bpam_faillock.so\s.*\bunlock_time\b" "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks "s/(.*auth.*pam_faillock.so.*)\bunlock_time\b=?[[:alnum:]]*(.*)/\1\2/g" "$PAM_FILE_PATH"
        fi
            if [ -f /usr/bin/authselect ]; then
                
                authselect apply-changes -b
            fi
        else
            echo "$pam_file was not found" >&2
        fi
    done
    
else
    for pam_file in "${AUTH_FILES[@]}"
    do
        if ! grep -qE '^\s*auth.*pam_faillock\.so (preauth|authfail).*unlock_time' "$pam_file"; then
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*preauth.*silent.*/ s/$/ unlock_time='"$var_accounts_passwords_pam_faillock_unlock_time"'/' "$pam_file"
            sed -i --follow-symlinks '/^auth.*required.*pam_faillock\.so.*authfail.*/ s/$/ unlock_time='"$var_accounts_passwords_pam_faillock_unlock_time"'/' "$pam_file"
        else
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*preauth.*silent.*\)\('"unlock_time"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_unlock_time"'\3/' "$pam_file"
            sed -i --follow-symlinks 's/\(^auth.*required.*pam_faillock\.so.*authfail.*\)\('"unlock_time"'=\)[0-9]\+\(.*\)/\1\2'"$var_accounts_passwords_pam_faillock_unlock_time"'\3/' "$pam_file"
        fi
    done
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_passwords_pam_faillock_unlock_time'

# ── FIXING: Accounts Password Pam Dictcheck ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_password_pam_dictcheck
# BEGIN fix (53 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_dictcheck'
###############################################################################
(>&2 echo "Remediating rule 53/379: 'xccdf_org.ssgproject.content_rule_accounts_password_pam_dictcheck'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_dictcheck='1'



if grep -sq dictcheck /etc/security/pwquality.conf.d/*.conf ; then
    sed -i "/dictcheck/d" /etc/security/pwquality.conf.d/*.conf
fi






# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^dictcheck")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_dictcheck"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^dictcheck\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^dictcheck\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-88413-0"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_dictcheck'

# ── FIXING: Accounts Password Pam Difok ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_password_pam_difok
# BEGIN fix (54 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_difok'
###############################################################################
(>&2 echo "Remediating rule 54/379: 'xccdf_org.ssgproject.content_rule_accounts_password_pam_difok'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_difok='2'



if grep -sq difok /etc/security/pwquality.conf.d/*.conf ; then
    sed -i "/difok/d" /etc/security/pwquality.conf.d/*.conf
fi






# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^difok")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_difok"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^difok\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^difok\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-83564-5"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_difok'

# ── FIXING: Accounts Password Pam Enforce Root ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_password_pam_enforce_root
# BEGIN fix (55 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_enforce_root'
###############################################################################
(>&2 echo "Remediating rule 55/379: 'xccdf_org.ssgproject.content_rule_accounts_password_pam_enforce_root'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

if [ -e "/etc/security/pwquality.conf" ] ; then
    
    LC_ALL=C sed -i "/^\s*enforce_for_root/Id" "/etc/security/pwquality.conf"
else
    touch "/etc/security/pwquality.conf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/security/pwquality.conf"

cp "/etc/security/pwquality.conf" "/etc/security/pwquality.conf.bak"
# Insert at the end of the file
printf '%s\n' "enforce_for_root" >> "/etc/security/pwquality.conf"
# Clean up after ourselves.
rm "/etc/security/pwquality.conf.bak"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_enforce_root'

# ── FIXING: Accounts Password Pam Maxrepeat ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_password_pam_maxrepeat
# BEGIN fix (56 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_maxrepeat'
###############################################################################
(>&2 echo "Remediating rule 56/379: 'xccdf_org.ssgproject.content_rule_accounts_password_pam_maxrepeat'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_maxrepeat='3'



if grep -sq maxrepeat /etc/security/pwquality.conf.d/*.conf ; then
    sed -i "/maxrepeat/d" /etc/security/pwquality.conf.d/*.conf
fi






# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^maxrepeat")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_maxrepeat"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^maxrepeat\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^maxrepeat\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-83567-8"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_maxrepeat'

# ── FIXING: Accounts Password Pam Minclass ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_password_pam_minclass
# BEGIN fix (57 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_minclass'
###############################################################################
(>&2 echo "Remediating rule 57/379: 'xccdf_org.ssgproject.content_rule_accounts_password_pam_minclass'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_minclass='4'



if grep -sq minclass /etc/security/pwquality.conf.d/*.conf ; then
    sed -i "/minclass/d" /etc/security/pwquality.conf.d/*.conf
fi






# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^minclass")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_minclass"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^minclass\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^minclass\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-83563-7"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_minclass'

# ── FIXING: Accounts Password Pam Minlen ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_password_pam_minlen
# BEGIN fix (58 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_minlen'
###############################################################################
(>&2 echo "Remediating rule 58/379: 'xccdf_org.ssgproject.content_rule_accounts_password_pam_minlen'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_pam_minlen='14'



if grep -sq minlen /etc/security/pwquality.conf.d/*.conf ; then
    sed -i "/minlen/d" /etc/security/pwquality.conf.d/*.conf
fi






# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^minlen")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$var_password_pam_minlen"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^minlen\\>" "/etc/security/pwquality.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^minlen\\>.*/$escaped_formatted_output/gi" "/etc/security/pwquality.conf"
else
    if [[ -s "/etc/security/pwquality.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/security/pwquality.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/security/pwquality.conf"
    fi
    cce="CCE-83579-3"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/security/pwquality.conf" >> "/etc/security/pwquality.conf"
    printf '%s\n' "$formatted_output" >> "/etc/security/pwquality.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_pam_minlen'

# ── FIXING: Set Password Hashing Algorithm Libuserconf ──
# Rule: xccdf_org.ssgproject.content_rule_set_password_hashing_algorithm_libuserconf
# BEGIN fix (59 / 379) for 'xccdf_org.ssgproject.content_rule_set_password_hashing_algorithm_libuserconf'
###############################################################################
(>&2 echo "Remediating rule 59/379: 'xccdf_org.ssgproject.content_rule_set_password_hashing_algorithm_libuserconf'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q libuser; then

var_password_hashing_algorithm_pam='sha512'

LIBUSER_CONF="/etc/libuser.conf"
CRYPT_STYLE_REGEX='[[:space:]]*\[defaults](.*(\n)+)+?[[:space:]]*crypt_style[[:space:]]*'

# Try find crypt_style in [defaults] section. If it is here, then change algorithm to sha512.
# If it isn't here, then add it to [defaults] section.
if grep -qzosP $CRYPT_STYLE_REGEX $LIBUSER_CONF ; then
        sed -i "s/\(crypt_style[[:space:]]*=[[:space:]]*\).*/\1$var_password_hashing_algorithm_pam/g" $LIBUSER_CONF
elif grep -qs "\[defaults]" $LIBUSER_CONF ; then
        sed -i "/[[:space:]]*\[defaults]/a crypt_style = $var_password_hashing_algorithm_pam" $LIBUSER_CONF
else
        echo -e "[defaults]\ncrypt_style = $var_password_hashing_algorithm_pam" >> $LIBUSER_CONF
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_set_password_hashing_algorithm_libuserconf'

# ── FIXING: Set Password Hashing Algorithm Logindefs ──
# Rule: xccdf_org.ssgproject.content_rule_set_password_hashing_algorithm_logindefs
# BEGIN fix (60 / 379) for 'xccdf_org.ssgproject.content_rule_set_password_hashing_algorithm_logindefs'
###############################################################################
(>&2 echo "Remediating rule 60/379: 'xccdf_org.ssgproject.content_rule_set_password_hashing_algorithm_logindefs'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

var_password_hashing_algorithm='SHA512'


# Allow multiple algorithms, but choose the first one for remediation
#
var_password_hashing_algorithm="$(echo $var_password_hashing_algorithm | cut -d \| -f 1)"

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^ENCRYPT_METHOD")

# shellcheck disable=SC2059
printf -v formatted_output "%s %s" "$stripped_key" "$var_password_hashing_algorithm"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^ENCRYPT_METHOD\\>" "/etc/login.defs"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^ENCRYPT_METHOD\\>.*/$escaped_formatted_output/gi" "/etc/login.defs"
else
    if [[ -s "/etc/login.defs" ]] && [[ -n "$(tail -c 1 -- "/etc/login.defs" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/login.defs"
    fi
    cce="CCE-90590-1"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/login.defs" >> "/etc/login.defs"
    printf '%s\n' "$formatted_output" >> "/etc/login.defs"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_set_password_hashing_algorithm_logindefs'

# ── FIXING: Set Password Hashing Algorithm Passwordauth ──
# Rule: xccdf_org.ssgproject.content_rule_set_password_hashing_algorithm_passwordauth
# BEGIN fix (61 / 379) for 'xccdf_org.ssgproject.content_rule_set_password_hashing_algorithm_passwordauth'
###############################################################################
(>&2 echo "Remediating rule 61/379: 'xccdf_org.ssgproject.content_rule_set_password_hashing_algorithm_passwordauth'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_hashing_algorithm_pam='sha512'

PAM_FILE_PATH="/etc/pam.d/password-auth"

if [ -e "$PAM_FILE_PATH" ] ; then
    PAM_FILE_PATH="$PAM_FILE_PATH"
    if [ -f /usr/bin/authselect ]; then
        
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi

        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        # If not already in use, a custom profile is created preserving the enabled features.
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            # The "local" profile does not contain essential security features required by multiple Benchmarks.
            # If currently used, it is replaced by "sssd", which is the best option in this case.
            if [[ $CURRENT_PROFILE == local ]]; then
                CURRENT_PROFILE="sssd"
            fi
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"
            
            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done
            
            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "$PAM_FILE_PATH")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

        authselect apply-changes -b
    fi
    

        if ! grep -qP "^\s*password\s+sufficient\s+pam_unix.so\s*.*" "$PAM_FILE_PATH"; then
            # Line matching group + control + module was not found. Check group + module.
            if [ "$(grep -cP '^\s*password\s+.*\s+pam_unix.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
                # The control is updated only if one single line matches.
                sed -i -E --follow-symlinks "s/^(\s*password\s+).*(\bpam_unix.so.*)/\1sufficient \2/" "$PAM_FILE_PATH"
            else
                echo "password    sufficient    pam_unix.so" >> "$PAM_FILE_PATH"
            fi
        fi
        # Check the option
        if ! grep -qP "^\s*password\s+sufficient\s+pam_unix.so\s*.*\s$var_password_hashing_algorithm_pam\b" "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks "/\s*password\s+sufficient\s+pam_unix.so.*/ s/$/ $var_password_hashing_algorithm_pam/" "$PAM_FILE_PATH"
        fi
    if [ -f /usr/bin/authselect ]; then
        
        authselect apply-changes -b
    fi
else
    echo "$PAM_FILE_PATH was not found" >&2
fi

# Ensure only the correct hashing algorithm option is used.
declare -a HASHING_ALGORITHMS_OPTIONS=("sha512" "yescrypt" "gost_yescrypt" "blowfish" "sha256" "md5" "bigcrypt")

for hash_option in "${HASHING_ALGORITHMS_OPTIONS[@]}"; do
  if [ "$hash_option" != "$var_password_hashing_algorithm_pam" ]; then
    if grep -qP "^\s*password\s+.*\s+pam_unix.so\s+.*\b$hash_option\b" "$PAM_FILE_PATH"; then
      if [ -e "$PAM_FILE_PATH" ] ; then
    PAM_FILE_PATH="$PAM_FILE_PATH"
    if [ -f /usr/bin/authselect ]; then
        
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi

        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        # If not already in use, a custom profile is created preserving the enabled features.
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            # The "local" profile does not contain essential security features required by multiple Benchmarks.
            # If currently used, it is replaced by "sssd", which is the best option in this case.
            if [[ $CURRENT_PROFILE == local ]]; then
                CURRENT_PROFILE="sssd"
            fi
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"
            
            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done
            
            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "$PAM_FILE_PATH")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

        authselect apply-changes -b
    fi
    
if grep -qP "^\s*password\s+.*\s+pam_unix.so\s.*\b$hash_option\b" "$PAM_FILE_PATH"; then
    sed -i -E --follow-symlinks "s/(.*password.*.*.*pam_unix.so.*)\s$hash_option=?[[:alnum:]]*(.*)/\1\2/g" "$PAM_FILE_PATH"
fi
    if [ -f /usr/bin/authselect ]; then
        
        authselect apply-changes -b
    fi
else
    echo "$PAM_FILE_PATH was not found" >&2
fi
    fi
  fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_set_password_hashing_algorithm_passwordauth'

# ── FIXING: Set Password Hashing Algorithm Systemauth ──
# Rule: xccdf_org.ssgproject.content_rule_set_password_hashing_algorithm_systemauth
# BEGIN fix (62 / 379) for 'xccdf_org.ssgproject.content_rule_set_password_hashing_algorithm_systemauth'
###############################################################################
(>&2 echo "Remediating rule 62/379: 'xccdf_org.ssgproject.content_rule_set_password_hashing_algorithm_systemauth'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_password_hashing_algorithm_pam='sha512'


PAM_FILE_PATH="/etc/pam.d/system-auth"


if [ -e "$PAM_FILE_PATH" ] ; then
    PAM_FILE_PATH="$PAM_FILE_PATH"
    if [ -f /usr/bin/authselect ]; then
        
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi

        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        # If not already in use, a custom profile is created preserving the enabled features.
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            # The "local" profile does not contain essential security features required by multiple Benchmarks.
            # If currently used, it is replaced by "sssd", which is the best option in this case.
            if [[ $CURRENT_PROFILE == local ]]; then
                CURRENT_PROFILE="sssd"
            fi
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"
            
            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done
            
            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "$PAM_FILE_PATH")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

        authselect apply-changes -b
    fi
    

        if ! grep -qP "^\s*password\s+sufficient\s+pam_unix.so\s*.*" "$PAM_FILE_PATH"; then
            # Line matching group + control + module was not found. Check group + module.
            if [ "$(grep -cP '^\s*password\s+.*\s+pam_unix.so\s*' "$PAM_FILE_PATH")" -eq 1 ]; then
                # The control is updated only if one single line matches.
                sed -i -E --follow-symlinks "s/^(\s*password\s+).*(\bpam_unix.so.*)/\1sufficient \2/" "$PAM_FILE_PATH"
            else
                echo "password    sufficient    pam_unix.so" >> "$PAM_FILE_PATH"
            fi
        fi
        # Check the option
        if ! grep -qP "^\s*password\s+sufficient\s+pam_unix.so\s*.*\s$var_password_hashing_algorithm_pam\b" "$PAM_FILE_PATH"; then
            sed -i -E --follow-symlinks "/\s*password\s+sufficient\s+pam_unix.so.*/ s/$/ $var_password_hashing_algorithm_pam/" "$PAM_FILE_PATH"
        fi
    if [ -f /usr/bin/authselect ]; then
        
        authselect apply-changes -b
    fi
else
    echo "$PAM_FILE_PATH was not found" >&2
fi

# Ensure only the correct hashing algorithm option is used.
declare -a HASHING_ALGORITHMS_OPTIONS=("sha512" "yescrypt" "gost_yescrypt" "blowfish" "sha256" "md5" "bigcrypt")

for hash_option in "${HASHING_ALGORITHMS_OPTIONS[@]}"; do
  if [ "$hash_option" != "$var_password_hashing_algorithm_pam" ]; then
    if grep -qP "^\s*password\s+.*\s+pam_unix.so\s+.*\b$hash_option\b" "$PAM_FILE_PATH"; then
      if [ -e "$PAM_FILE_PATH" ] ; then
    PAM_FILE_PATH="$PAM_FILE_PATH"
    if [ -f /usr/bin/authselect ]; then
        
        if ! authselect check; then
        echo "
        authselect integrity check failed. Remediation aborted!
        This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
        It is not recommended to manually edit the PAM files when authselect tool is available.
        In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
        exit 1
        fi

        CURRENT_PROFILE=$(authselect current -r | awk '{ print $1 }')
        # If not already in use, a custom profile is created preserving the enabled features.
        if [[ ! $CURRENT_PROFILE == custom/* ]]; then
            ENABLED_FEATURES=$(authselect current | tail -n+3 | awk '{ print $2 }')
            # The "local" profile does not contain essential security features required by multiple Benchmarks.
            # If currently used, it is replaced by "sssd", which is the best option in this case.
            if [[ $CURRENT_PROFILE == local ]]; then
                CURRENT_PROFILE="sssd"
            fi
            authselect create-profile hardening -b $CURRENT_PROFILE
            CURRENT_PROFILE="custom/hardening"
            
            authselect apply-changes -b --backup=before-hardening-custom-profile
            authselect select $CURRENT_PROFILE
            for feature in $ENABLED_FEATURES; do
                authselect enable-feature $feature;
            done
            
            authselect apply-changes -b --backup=after-hardening-custom-profile
        fi
        PAM_FILE_NAME=$(basename "$PAM_FILE_PATH")
        PAM_FILE_PATH="/etc/authselect/$CURRENT_PROFILE/$PAM_FILE_NAME"

        authselect apply-changes -b
    fi
    
if grep -qP "^\s*password\s+.*\s+pam_unix.so\s.*\b$hash_option\b" "$PAM_FILE_PATH"; then
    sed -i -E --follow-symlinks "s/(.*password.*.*.*pam_unix.so.*)\s$hash_option=?[[:alnum:]]*(.*)/\1\2/g" "$PAM_FILE_PATH"
fi
    if [ -f /usr/bin/authselect ]; then
        
        authselect apply-changes -b
    fi
else
    echo "$PAM_FILE_PATH was not found" >&2
fi
    fi
  fi
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_set_password_hashing_algorithm_systemauth'

# ── FIXING: Account Unique Id ──
# Rule: xccdf_org.ssgproject.content_rule_account_unique_id
# BEGIN fix (63 / 379) for 'xccdf_org.ssgproject.content_rule_account_unique_id'
###############################################################################
(>&2 echo "Remediating rule 63/379: 'xccdf_org.ssgproject.content_rule_account_unique_id'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_account_unique_id' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_account_unique_id'

# ── FIXING: Group Unique Id ──
# Rule: xccdf_org.ssgproject.content_rule_group_unique_id
# BEGIN fix (64 / 379) for 'xccdf_org.ssgproject.content_rule_group_unique_id'
###############################################################################
(>&2 echo "Remediating rule 64/379: 'xccdf_org.ssgproject.content_rule_group_unique_id'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_group_unique_id' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_group_unique_id'

# ── FIXING: Account Disable Post Pw Expiration ──
# Rule: xccdf_org.ssgproject.content_rule_account_disable_post_pw_expiration
# BEGIN fix (65 / 379) for 'xccdf_org.ssgproject.content_rule_account_disable_post_pw_expiration'
###############################################################################
(>&2 echo "Remediating rule 65/379: 'xccdf_org.ssgproject.content_rule_account_disable_post_pw_expiration'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

var_account_disable_post_pw_expiration='45'


# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^INACTIVE")

# shellcheck disable=SC2059
printf -v formatted_output "%s=%s" "$stripped_key" "$var_account_disable_post_pw_expiration"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^INACTIVE\\>" "/etc/default/useradd"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^INACTIVE\\>.*/$escaped_formatted_output/gi" "/etc/default/useradd"
else
    if [[ -s "/etc/default/useradd" ]] && [[ -n "$(tail -c 1 -- "/etc/default/useradd" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/default/useradd"
    fi
    cce="CCE-83627-0"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/default/useradd" >> "/etc/default/useradd"
    printf '%s\n' "$formatted_output" >> "/etc/default/useradd"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_account_disable_post_pw_expiration'

# ── FIXING: Account Unique Name ──
# Rule: xccdf_org.ssgproject.content_rule_account_unique_name
# BEGIN fix (66 / 379) for 'xccdf_org.ssgproject.content_rule_account_unique_name'
###############################################################################
(>&2 echo "Remediating rule 66/379: 'xccdf_org.ssgproject.content_rule_account_unique_name'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_account_unique_name' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_account_unique_name'

# ── FIXING: Accounts Maximum Age Login Defs ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_maximum_age_login_defs
# BEGIN fix (67 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_maximum_age_login_defs'
###############################################################################
(>&2 echo "Remediating rule 67/379: 'xccdf_org.ssgproject.content_rule_accounts_maximum_age_login_defs'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

var_accounts_maximum_age_login_defs='365'

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^PASS_MAX_DAYS")

# shellcheck disable=SC2059
printf -v formatted_output "%s %s" "$stripped_key" "$var_accounts_maximum_age_login_defs"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^PASS_MAX_DAYS\\>" "/etc/login.defs"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^PASS_MAX_DAYS\\>.*/$escaped_formatted_output/gi" "/etc/login.defs"
else
    if [[ -s "/etc/login.defs" ]] && [[ -n "$(tail -c 1 -- "/etc/login.defs" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/login.defs"
    fi
    cce="CCE-83606-4"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/login.defs" >> "/etc/login.defs"
    printf '%s\n' "$formatted_output" >> "/etc/login.defs"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_maximum_age_login_defs'

# ── FIXING: Accounts Minimum Age Login Defs ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_minimum_age_login_defs
# BEGIN fix (68 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_minimum_age_login_defs'
###############################################################################
(>&2 echo "Remediating rule 68/379: 'xccdf_org.ssgproject.content_rule_accounts_minimum_age_login_defs'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

var_accounts_minimum_age_login_defs='1'

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^PASS_MIN_DAYS")

# shellcheck disable=SC2059
printf -v formatted_output "%s %s" "$stripped_key" "$var_accounts_minimum_age_login_defs"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^PASS_MIN_DAYS\\>" "/etc/login.defs"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^PASS_MIN_DAYS\\>.*/$escaped_formatted_output/gi" "/etc/login.defs"
else
    if [[ -s "/etc/login.defs" ]] && [[ -n "$(tail -c 1 -- "/etc/login.defs" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/login.defs"
    fi
    cce="CCE-83610-6"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/login.defs" >> "/etc/login.defs"
    printf '%s\n' "$formatted_output" >> "/etc/login.defs"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_minimum_age_login_defs'

# ── FIXING: Accounts Password Set Max Life Existing ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_password_set_max_life_existing
# BEGIN fix (69 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_password_set_max_life_existing'
###############################################################################
(>&2 echo "Remediating rule 69/379: 'xccdf_org.ssgproject.content_rule_accounts_password_set_max_life_existing'"); (

var_accounts_maximum_age_login_defs='365'


while IFS= read -r i; do
    
    chage -M $var_accounts_maximum_age_login_defs $i

done <   <(awk -v var="$var_accounts_maximum_age_login_defs" -F: '(/^[^:]+:[^!*]/ && ($5 > var || $5 == "")) {print $1}' /etc/shadow)

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_set_max_life_existing'

# ── FIXING: Accounts Password Set Min Life Existing ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_password_set_min_life_existing
# BEGIN fix (70 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_password_set_min_life_existing'
###############################################################################
(>&2 echo "Remediating rule 70/379: 'xccdf_org.ssgproject.content_rule_accounts_password_set_min_life_existing'"); (

var_accounts_minimum_age_login_defs='1'


while IFS= read -r i; do
    
    chage -m $var_accounts_minimum_age_login_defs $i

done <   <(awk -v var="$var_accounts_minimum_age_login_defs" -F: '(/^[^:]+:[^!*]/ && ($4 < var || $4 == "")) {print $1}' /etc/shadow)

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_set_min_life_existing'

# ── FIXING: Accounts Password Set Warn Age Existing ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_password_set_warn_age_existing
# BEGIN fix (71 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_password_set_warn_age_existing'
###############################################################################
(>&2 echo "Remediating rule 71/379: 'xccdf_org.ssgproject.content_rule_accounts_password_set_warn_age_existing'"); (

var_accounts_password_warn_age_login_defs='7'


while IFS= read -r i; do
    chage --warndays $var_accounts_password_warn_age_login_defs $i
done <   <(awk -v var="$var_accounts_password_warn_age_login_defs" -F: '(($6 < var || $6 == "") && $2 ~ /^\$/) {print $1}' /etc/shadow)

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_set_warn_age_existing'

# ── FIXING: Accounts Password Warn Age Login Defs ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_password_warn_age_login_defs
# BEGIN fix (72 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_password_warn_age_login_defs'
###############################################################################
(>&2 echo "Remediating rule 72/379: 'xccdf_org.ssgproject.content_rule_accounts_password_warn_age_login_defs'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

var_accounts_password_warn_age_login_defs='7'

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^PASS_WARN_AGE")

# shellcheck disable=SC2059
printf -v formatted_output "%s %s" "$stripped_key" "$var_accounts_password_warn_age_login_defs"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^PASS_WARN_AGE\\>" "/etc/login.defs"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^PASS_WARN_AGE\\>.*/$escaped_formatted_output/gi" "/etc/login.defs"
else
    if [[ -s "/etc/login.defs" ]] && [[ -n "$(tail -c 1 -- "/etc/login.defs" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/login.defs"
    fi
    cce="CCE-83609-8"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/login.defs" >> "/etc/login.defs"
    printf '%s\n' "$formatted_output" >> "/etc/login.defs"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_warn_age_login_defs'

# ── FIXING: Accounts Set Post Pw Existing ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_set_post_pw_existing
# BEGIN fix (73 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_set_post_pw_existing'
###############################################################################
(>&2 echo "Remediating rule 73/379: 'xccdf_org.ssgproject.content_rule_accounts_set_post_pw_existing'"); (

var_account_disable_post_pw_expiration='45'


while IFS= read -r i; do
    chage --inactive $var_account_disable_post_pw_expiration $i
done <   <(awk -v var="$var_account_disable_post_pw_expiration" -F: '(($7 > var || $7 == "") && $2 ~ /^\$/) {print $1}' /etc/shadow)

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_set_post_pw_existing'

# ── FIXING: Accounts Password All Shadowed ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_password_all_shadowed
# BEGIN fix (74 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_password_all_shadowed'
###############################################################################
(>&2 echo "Remediating rule 74/379: 'xccdf_org.ssgproject.content_rule_accounts_password_all_shadowed'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_accounts_password_all_shadowed' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_all_shadowed'

# ── FIXING: Accounts Password Last Change Is In Past ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_password_last_change_is_in_past
# BEGIN fix (75 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_password_last_change_is_in_past'
###############################################################################
(>&2 echo "Remediating rule 75/379: 'xccdf_org.ssgproject.content_rule_accounts_password_last_change_is_in_past'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_accounts_password_last_change_is_in_past' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_password_last_change_is_in_past'

# ── FIXING: Gid Passwd Group Same ──
# Rule: xccdf_org.ssgproject.content_rule_gid_passwd_group_same
# BEGIN fix (76 / 379) for 'xccdf_org.ssgproject.content_rule_gid_passwd_group_same'
###############################################################################
(>&2 echo "Remediating rule 76/379: 'xccdf_org.ssgproject.content_rule_gid_passwd_group_same'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_gid_passwd_group_same' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_gid_passwd_group_same'

# ── FIXING: No Empty Passwords ──
# Rule: xccdf_org.ssgproject.content_rule_no_empty_passwords
# BEGIN fix (77 / 379) for 'xccdf_org.ssgproject.content_rule_no_empty_passwords'
###############################################################################
(>&2 echo "Remediating rule 77/379: 'xccdf_org.ssgproject.content_rule_no_empty_passwords'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if [ -f /usr/bin/authselect ]; then
    if ! authselect check; then
echo "
authselect integrity check failed. Remediation aborted!
This remediation could not be applied because an authselect profile was not selected or the selected profile is not intact.
It is not recommended to manually edit the PAM files when authselect tool is available.
In cases where the default authselect profile does not cover a specific demand, a custom authselect profile is recommended."
exit 1
fi
authselect enable-feature without-nullok

authselect apply-changes -b
else
    
if grep -qP "^\s*auth\s+sufficient\s+pam_unix.so\s.*\bnullok\b" "/etc/pam.d/system-auth"; then
    sed -i -E --follow-symlinks "s/(.*auth.*sufficient.*pam_unix.so.*)\snullok=?[[:alnum:]]*(.*)/\1\2/g" "/etc/pam.d/system-auth"
fi
    
if grep -qP "^\s*password\s+sufficient\s+pam_unix.so\s.*\bnullok\b" "/etc/pam.d/system-auth"; then
    sed -i -E --follow-symlinks "s/(.*password.*sufficient.*pam_unix.so.*)\snullok=?[[:alnum:]]*(.*)/\1\2/g" "/etc/pam.d/system-auth"
fi
    
if grep -qP "^\s*auth\s+sufficient\s+pam_unix.so\s.*\bnullok\b" "/etc/pam.d/password-auth"; then
    sed -i -E --follow-symlinks "s/(.*auth.*sufficient.*pam_unix.so.*)\snullok=?[[:alnum:]]*(.*)/\1\2/g" "/etc/pam.d/password-auth"
fi
    
if grep -qP "^\s*password\s+sufficient\s+pam_unix.so\s.*\bnullok\b" "/etc/pam.d/password-auth"; then
    sed -i -E --follow-symlinks "s/(.*password.*sufficient.*pam_unix.so.*)\snullok=?[[:alnum:]]*(.*)/\1\2/g" "/etc/pam.d/password-auth"
fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_no_empty_passwords'

# ── FIXING: No Empty Passwords Etc Shadow ──
# Rule: xccdf_org.ssgproject.content_rule_no_empty_passwords_etc_shadow
# BEGIN fix (78 / 379) for 'xccdf_org.ssgproject.content_rule_no_empty_passwords_etc_shadow'
###############################################################################
(>&2 echo "Remediating rule 78/379: 'xccdf_org.ssgproject.content_rule_no_empty_passwords_etc_shadow'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

readarray -t users_with_empty_pass < <(sudo awk -F: '!$2 {print $1}' /etc/shadow)

for user_with_empty_pass in "${users_with_empty_pass[@]}"
do
    passwd -l $user_with_empty_pass
done

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_no_empty_passwords_etc_shadow'

# ── FIXING: No Forward Files ──
# Rule: xccdf_org.ssgproject.content_rule_no_forward_files
# BEGIN fix (79 / 379) for 'xccdf_org.ssgproject.content_rule_no_forward_files'
###############################################################################
(>&2 echo "Remediating rule 79/379: 'xccdf_org.ssgproject.content_rule_no_forward_files'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_no_forward_files' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_no_forward_files'

# ── FIXING: No Netrc Files ──
# Rule: xccdf_org.ssgproject.content_rule_no_netrc_files
# BEGIN fix (80 / 379) for 'xccdf_org.ssgproject.content_rule_no_netrc_files'
###############################################################################
(>&2 echo "Remediating rule 80/379: 'xccdf_org.ssgproject.content_rule_no_netrc_files'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_no_netrc_files' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_no_netrc_files'

# ── FIXING: Accounts No Uid Except Zero ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_no_uid_except_zero
# BEGIN fix (81 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_no_uid_except_zero'
###############################################################################
(>&2 echo "Remediating rule 81/379: 'xccdf_org.ssgproject.content_rule_accounts_no_uid_except_zero'"); (
awk -F: '$3 == 0 && $1 != "root" { print $1 }' /etc/passwd | xargs --no-run-if-empty --max-lines=1 passwd -l

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_no_uid_except_zero'

# ── FIXING: Accounts Root Gid Zero ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_root_gid_zero
# BEGIN fix (82 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_root_gid_zero'
###############################################################################
(>&2 echo "Remediating rule 82/379: 'xccdf_org.ssgproject.content_rule_accounts_root_gid_zero'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_accounts_root_gid_zero' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_root_gid_zero'

# ── FIXING: Ensure Pam Wheel Group Empty ──
# Rule: xccdf_org.ssgproject.content_rule_ensure_pam_wheel_group_empty
# BEGIN fix (83 / 379) for 'xccdf_org.ssgproject.content_rule_ensure_pam_wheel_group_empty'
###############################################################################
(>&2 echo "Remediating rule 83/379: 'xccdf_org.ssgproject.content_rule_ensure_pam_wheel_group_empty'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_pam_wheel_group_for_su='sugroup'


if ! grep -q "^${var_pam_wheel_group_for_su}:[^:]*:[^:]*:[^:]*" /etc/group; then
    groupadd ${var_pam_wheel_group_for_su}
fi

# group must be empty
gpasswd -M '' ${var_pam_wheel_group_for_su}

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_ensure_pam_wheel_group_empty'

# ── FIXING: Ensure Root Password Configured ──
# Rule: xccdf_org.ssgproject.content_rule_ensure_root_password_configured
# BEGIN fix (84 / 379) for 'xccdf_org.ssgproject.content_rule_ensure_root_password_configured'
###############################################################################
(>&2 echo "Remediating rule 84/379: 'xccdf_org.ssgproject.content_rule_ensure_root_password_configured'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_ensure_root_password_configured' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_ensure_root_password_configured'

# ── FIXING: No Password Auth For Systemaccounts ──
# Rule: xccdf_org.ssgproject.content_rule_no_password_auth_for_systemaccounts
# BEGIN fix (85 / 379) for 'xccdf_org.ssgproject.content_rule_no_password_auth_for_systemaccounts'
###############################################################################
(>&2 echo "Remediating rule 85/379: 'xccdf_org.ssgproject.content_rule_no_password_auth_for_systemaccounts'"); (

readarray -t systemaccounts < <(awk -F: \
  '($3 < 1000 && $3 != root && $3 != halt && $3 != sync && $3 != shutdown \
  && $3 != nfsnobody) { print $1 }' /etc/passwd)

for systemaccount in "${systemaccounts[@]}"; do
    usermod -L "$systemaccount"
done

) # END fix for 'xccdf_org.ssgproject.content_rule_no_password_auth_for_systemaccounts'

# ── FIXING: No Shelllogin For Systemaccounts ──
# Rule: xccdf_org.ssgproject.content_rule_no_shelllogin_for_systemaccounts
# BEGIN fix (86 / 379) for 'xccdf_org.ssgproject.content_rule_no_shelllogin_for_systemaccounts'
###############################################################################
(>&2 echo "Remediating rule 86/379: 'xccdf_org.ssgproject.content_rule_no_shelllogin_for_systemaccounts'"); (

readarray -t systemaccounts < <(awk -F: '($3 < 1000 && $3 != root \
  && $7 != "\/sbin\/shutdown" && $7 != "\/sbin\/halt" && $7 != "\/bin\/sync") \
  { print $1 }' /etc/passwd)

for systemaccount in "${systemaccounts[@]}"; do
    usermod -s /sbin/nologin "$systemaccount"
done

) # END fix for 'xccdf_org.ssgproject.content_rule_no_shelllogin_for_systemaccounts'

# ── FIXING: Use Pam Wheel Group For Su ──
# Rule: xccdf_org.ssgproject.content_rule_use_pam_wheel_group_for_su
# BEGIN fix (87 / 379) for 'xccdf_org.ssgproject.content_rule_use_pam_wheel_group_for_su'
###############################################################################
(>&2 echo "Remediating rule 87/379: 'xccdf_org.ssgproject.content_rule_use_pam_wheel_group_for_su'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q pam; then

var_pam_wheel_group_for_su='sugroup'


PAM_CONF=/etc/pam.d/su

pamstr=$(grep -P '^auth\s+required\s+pam_wheel\.so\s+(?=[^#]*\buse_uid\b)(?=[^#]*\bgroup=)' ${PAM_CONF})
if [ -z "$pamstr" ]; then
    sed -Ei '/^auth\b.*\brequired\b.*\bpam_wheel\.so/d' ${PAM_CONF} # remove any remaining uncommented pam_wheel.so line
    sed -Ei "/^auth\s+sufficient\s+pam_rootok\.so.*$/a auth             required        pam_wheel.so use_uid group=${var_pam_wheel_group_for_su}" ${PAM_CONF}
else
    group_val=$(echo -n "$pamstr" | grep -Eo '\bgroup=[_a-z][-0-9_a-z]*' | cut -d '=' -f 2)
    if [ -z "${group_val}" ] || [ ${group_val} != ${var_pam_wheel_group_for_su} ]; then
        sed -Ei "s/(^auth\s+required\s+pam_wheel.so\s+[^#]*group=)[_a-z][-0-9_a-z]*/\1${var_pam_wheel_group_for_su}/" ${PAM_CONF}
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_use_pam_wheel_group_for_su'

# ── FIXING: Accounts Tmout ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_tmout
# BEGIN fix (88 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_tmout'
###############################################################################
(>&2 echo "Remediating rule 88/379: 'xccdf_org.ssgproject.content_rule_accounts_tmout'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

var_accounts_tmout='900'


# if 0, no occurence of tmout found, if 1, occurence found
tmout_found=0


for f in /etc/profile /etc/profile.d/*.sh; do

    if grep --silent '^[^#].*TMOUT' $f; then
        sed -i -E "s/^(.*)TMOUT\s*=\s*(\w|\$)*(.*)$/typeset -xr TMOUT=$var_accounts_tmout\3/g" $f
        tmout_found=1
    fi
done

if [ $tmout_found -eq 0 ]; then
        echo -e "\n# Set TMOUT to $var_accounts_tmout per security requirements" >> /etc/profile.d/tmout.sh
        echo "typeset -xr TMOUT=$var_accounts_tmout" >> /etc/profile.d/tmout.sh
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_tmout'

# ── FIXING: Accounts User Dot Group Ownership ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_user_dot_group_ownership
# BEGIN fix (89 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_user_dot_group_ownership'
###############################################################################
(>&2 echo "Remediating rule 89/379: 'xccdf_org.ssgproject.content_rule_accounts_user_dot_group_ownership'"); (

awk -F':' '{ if ($3 >= 1000 && $3 != 65534) system("chgrp -f " $4" "$6"/.[^\.]?*") }' /etc/passwd

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_user_dot_group_ownership'

# ── FIXING: Accounts User Dot No World Writable Programs ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_user_dot_no_world_writable_programs
# BEGIN fix (90 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_user_dot_no_world_writable_programs'
###############################################################################
(>&2 echo "Remediating rule 90/379: 'xccdf_org.ssgproject.content_rule_accounts_user_dot_no_world_writable_programs'"); (

readarray -t world_writable_files < <(find / -xdev -type f -perm -0002 2> /dev/null)
readarray -t interactive_home_dirs < <(awk -F':' '{ if ($3 >= 1000 && $3 != 65534) print $6 }' /etc/passwd)

for world_writable in "${world_writable_files[@]}"; do
    for homedir in "${interactive_home_dirs[@]}"; do
        if grep -q -d skip "$world_writable" "$homedir"/.*; then
            chmod o-w $world_writable
            break
        fi
    done
done

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_user_dot_no_world_writable_programs'

# ── FIXING: Accounts User Dot User Ownership ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_user_dot_user_ownership
# BEGIN fix (91 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_user_dot_user_ownership'
###############################################################################
(>&2 echo "Remediating rule 91/379: 'xccdf_org.ssgproject.content_rule_accounts_user_dot_user_ownership'"); (

awk -F':' '{ if ($3 >= 1000 && $3 != 65534) system("chown -f " $3" "$6"/.[^\.]?*") }' /etc/passwd

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_user_dot_user_ownership'

# ── FIXING: Accounts User Interactive Home Directory Exists ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_user_interactive_home_directory_exists
# BEGIN fix (92 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_user_interactive_home_directory_exists'
###############################################################################
(>&2 echo "Remediating rule 92/379: 'xccdf_org.ssgproject.content_rule_accounts_user_interactive_home_directory_exists'"); (

for user in $(awk -F':' '{ if ($3 >= 1000 && $3 != 65534) print $1}' /etc/passwd); do
    mkhomedir_helper $user 0077;
done

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_user_interactive_home_directory_exists'

# ── FIXING: Accounts Root Path Dirs No Write ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_root_path_dirs_no_write
# BEGIN fix (95 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_root_path_dirs_no_write'
###############################################################################
(>&2 echo "Remediating rule 95/379: 'xccdf_org.ssgproject.content_rule_accounts_root_path_dirs_no_write'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_accounts_root_path_dirs_no_write' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_root_path_dirs_no_write'

# ── FIXING: Root Path No Dot ──
# Rule: xccdf_org.ssgproject.content_rule_root_path_no_dot
# BEGIN fix (96 / 379) for 'xccdf_org.ssgproject.content_rule_root_path_no_dot'
###############################################################################
(>&2 echo "Remediating rule 96/379: 'xccdf_org.ssgproject.content_rule_root_path_no_dot'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_root_path_no_dot' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_root_path_no_dot'

# ── FIXING: Accounts Umask Etc Bashrc ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_umask_etc_bashrc
# BEGIN fix (97 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_umask_etc_bashrc'
###############################################################################
(>&2 echo "Remediating rule 97/379: 'xccdf_org.ssgproject.content_rule_accounts_umask_etc_bashrc'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q bash; then

var_accounts_user_umask='027'






grep -q "^[^#]*\bumask" /etc/bashrc && \
  sed -i -E -e "s/^([^#]*\bumask)[[:space:]]+[[:digit:]]+/\1 $var_accounts_user_umask/g" /etc/bashrc
if ! [ $? -eq 0 ]; then
    echo "umask $var_accounts_user_umask" >> /etc/bashrc
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_umask_etc_bashrc'

# ── FIXING: Accounts Umask Etc Login Defs ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_umask_etc_login_defs
# BEGIN fix (98 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_umask_etc_login_defs'
###############################################################################
(>&2 echo "Remediating rule 98/379: 'xccdf_org.ssgproject.content_rule_accounts_umask_etc_login_defs'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q shadow-utils; then

var_accounts_user_umask='027'


# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^UMASK")

# shellcheck disable=SC2059
printf -v formatted_output "%s %s" "$stripped_key" "$var_accounts_user_umask"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^UMASK\\>" "/etc/login.defs"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^UMASK\\>.*/$escaped_formatted_output/gi" "/etc/login.defs"
else
    if [[ -s "/etc/login.defs" ]] && [[ -n "$(tail -c 1 -- "/etc/login.defs" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/login.defs"
    fi
    cce="CCE-83647-8"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/login.defs" >> "/etc/login.defs"
    printf '%s\n' "$formatted_output" >> "/etc/login.defs"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_umask_etc_login_defs'

# ── FIXING: Accounts Umask Etc Profile ──
# Rule: xccdf_org.ssgproject.content_rule_accounts_umask_etc_profile
# BEGIN fix (99 / 379) for 'xccdf_org.ssgproject.content_rule_accounts_umask_etc_profile'
###############################################################################
(>&2 echo "Remediating rule 99/379: 'xccdf_org.ssgproject.content_rule_accounts_umask_etc_profile'"); (

var_accounts_user_umask='027'


readarray -t profile_files < <(find /etc/profile.d/ -type f -name '*.sh' -or -name 'sh.local')

for file in "${profile_files[@]}" /etc/profile; do
  grep -qE '^[^#]*umask' "$file" && sed -i -E "s/^(\s*umask\s*)[0-7]+/\1$var_accounts_user_umask/g" "$file"
done

if ! grep -qrE '^[^#]*umask' /etc/profile*; then
  echo "umask $var_accounts_user_umask" >> /etc/profile
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_accounts_umask_etc_profile'
