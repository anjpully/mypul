#!/bin/bash
#
# RHEL 9 OSCAP Remediation - GNOME / GDM GUI Hardening
# Description: GNOME/GDM dconf settings: screen lock delay, login banner, disable automount/autorun, disable user list at login, XDMCP disable, etc.
# Rules covered: 12
#
# Usage: Run as root: bash 14_gnome_and_gui.sh
#

set -o nounset


# ── FIXING: Dconf Db Up To Date ──
# Rule: xccdf_org.ssgproject.content_rule_dconf_db_up_to_date
# BEGIN fix (14 / 379) for 'xccdf_org.ssgproject.content_rule_dconf_db_up_to_date'
###############################################################################
(>&2 echo "Remediating rule 14/379: 'xccdf_org.ssgproject.content_rule_dconf_db_up_to_date'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { rpm --quiet -q kernel; }; then

dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_dconf_db_up_to_date'

# ── FIXING: Dconf Gnome Disable User List ──
# Rule: xccdf_org.ssgproject.content_rule_dconf_gnome_disable_user_list
# BEGIN fix (15 / 379) for 'xccdf_org.ssgproject.content_rule_dconf_gnome_disable_user_list'
###############################################################################
(>&2 echo "Remediating rule 15/379: 'xccdf_org.ssgproject.content_rule_dconf_gnome_disable_user_list'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/login-screen\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|distro.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/distro.d/00-security-settings"
DBDIR="/etc/dconf/db/distro.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*disable-user-list\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)disable-user-list(\s*=)/#\1disable-user-list\2/g" "${SETTINGSFILES[@]}"
    fi
fi

[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/login-screen\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/login-screen]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "true")"
if grep -q "^\\s*disable-user-list\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*disable-user-list\\s*=\\s*.*/disable-user-list=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/login-screen\\]|a\\disable-user-list=${escaped_value}" "${DCONFFILE}"
fi
dconf update
# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/login-screen/disable-user-list$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|distro.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/distro.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/login-screen/disable-user-list$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/login-screen/disable-user-list$" /etc/dconf/db/distro.d/
then
    echo "/org/gnome/login-screen/disable-user-list" >> "/etc/dconf/db/distro.d/locks/00-security-settings-lock"
fi
dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_dconf_gnome_disable_user_list'

# ── FIXING: Gnome Gdm Disable Xdmcp ──
# Rule: xccdf_org.ssgproject.content_rule_gnome_gdm_disable_xdmcp
# BEGIN fix (16 / 379) for 'xccdf_org.ssgproject.content_rule_gnome_gdm_disable_xdmcp'
###############################################################################
(>&2 echo "Remediating rule 16/379: 'xccdf_org.ssgproject.content_rule_gnome_gdm_disable_xdmcp'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm; then

# Try find '[xdmcp]' and 'Enable' in '/etc/gdm/custom.conf', if it exists, set
# to 'false', if it isn't here, add it, if '[xdmcp]' doesn't exist, add it there
if grep -qzosP '[[:space:]]*\[xdmcp]([^\n\[]*\n+)+?[[:space:]]*Enable' '/etc/gdm/custom.conf'; then
    
    sed -i "s/Enable[^(\n)]*/Enable=false/" '/etc/gdm/custom.conf'
elif grep -qs '[[:space:]]*\[xdmcp]' '/etc/gdm/custom.conf'; then
    sed -i "/[[:space:]]*\[xdmcp]/a Enable=false" '/etc/gdm/custom.conf'
else
    if test -d "/etc/gdm"; then
        printf '%s\n' '[xdmcp]' "Enable=false" >> '/etc/gdm/custom.conf'
    else
        echo "Config file directory '/etc/gdm' doesnt exist, not remediating, assuming non-applicability." >&2
    fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_gnome_gdm_disable_xdmcp'

# ── FIXING: Dconf Gnome Disable Automount ──
# Rule: xccdf_org.ssgproject.content_rule_dconf_gnome_disable_automount
# BEGIN fix (17 / 379) for 'xccdf_org.ssgproject.content_rule_dconf_gnome_disable_automount'
###############################################################################
(>&2 echo "Remediating rule 17/379: 'xccdf_org.ssgproject.content_rule_dconf_gnome_disable_automount'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/media-handling\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
DBDIR="/etc/dconf/db/local.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*automount\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)automount(\s*=)/#\1automount\2/g" "${SETTINGSFILES[@]}"
    fi
fi

[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/desktop/media-handling\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/desktop/media-handling]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "false")"
if grep -q "^\\s*automount\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*automount\\s*=\\s*.*/automount=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/desktop/media-handling\\]|a\\automount=${escaped_value}" "${DCONFFILE}"
fi
dconf update
# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/desktop/media-handling/automount$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/desktop/media-handling/automount$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/desktop/media-handling/automount$" /etc/dconf/db/local.d/
then
    echo "/org/gnome/desktop/media-handling/automount" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
fi
dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_dconf_gnome_disable_automount'

# ── FIXING: Dconf Gnome Disable Automount Open ──
# Rule: xccdf_org.ssgproject.content_rule_dconf_gnome_disable_automount_open
# BEGIN fix (18 / 379) for 'xccdf_org.ssgproject.content_rule_dconf_gnome_disable_automount_open'
###############################################################################
(>&2 echo "Remediating rule 18/379: 'xccdf_org.ssgproject.content_rule_dconf_gnome_disable_automount_open'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/media-handling\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
DBDIR="/etc/dconf/db/local.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*automount-open\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)automount-open(\s*=)/#\1automount-open\2/g" "${SETTINGSFILES[@]}"
    fi
fi

[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/desktop/media-handling\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/desktop/media-handling]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "false")"
if grep -q "^\\s*automount-open\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*automount-open\\s*=\\s*.*/automount-open=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/desktop/media-handling\\]|a\\automount-open=${escaped_value}" "${DCONFFILE}"
fi
dconf update
# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/desktop/media-handling/automount-open$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/desktop/media-handling/automount-open$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/desktop/media-handling/automount-open$" /etc/dconf/db/local.d/
then
    echo "/org/gnome/desktop/media-handling/automount-open" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
fi
dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_dconf_gnome_disable_automount_open'

# ── FIXING: Dconf Gnome Disable Autorun ──
# Rule: xccdf_org.ssgproject.content_rule_dconf_gnome_disable_autorun
# BEGIN fix (19 / 379) for 'xccdf_org.ssgproject.content_rule_dconf_gnome_disable_autorun'
###############################################################################
(>&2 echo "Remediating rule 19/379: 'xccdf_org.ssgproject.content_rule_dconf_gnome_disable_autorun'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/media-handling\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
DBDIR="/etc/dconf/db/local.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*autorun-never\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)autorun-never(\s*=)/#\1autorun-never\2/g" "${SETTINGSFILES[@]}"
    fi
fi

[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/desktop/media-handling\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/desktop/media-handling]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "true")"
if grep -q "^\\s*autorun-never\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*autorun-never\\s*=\\s*.*/autorun-never=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/desktop/media-handling\\]|a\\autorun-never=${escaped_value}" "${DCONFFILE}"
fi
dconf update
# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/desktop/media-handling/autorun-never$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/desktop/media-handling/autorun-never$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/desktop/media-handling/autorun-never$" /etc/dconf/db/local.d/
then
    echo "/org/gnome/desktop/media-handling/autorun-never" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
fi
dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_dconf_gnome_disable_autorun'

# ── FIXING: Dconf Gnome Screensaver Idle Delay ──
# Rule: xccdf_org.ssgproject.content_rule_dconf_gnome_screensaver_idle_delay
# BEGIN fix (20 / 379) for 'xccdf_org.ssgproject.content_rule_dconf_gnome_screensaver_idle_delay'
###############################################################################
(>&2 echo "Remediating rule 20/379: 'xccdf_org.ssgproject.content_rule_dconf_gnome_screensaver_idle_delay'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

inactivity_timeout_value='900'


# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/session\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
DBDIR="/etc/dconf/db/local.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*idle-delay\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)idle-delay(\s*=)/#\1idle-delay\2/g" "${SETTINGSFILES[@]}"
    fi
fi

[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/desktop/session\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/desktop/session]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "uint32 ${inactivity_timeout_value}")"
if grep -q "^\\s*idle-delay\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*idle-delay\\s*=\\s*.*/idle-delay=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/desktop/session\\]|a\\idle-delay=${escaped_value}" "${DCONFFILE}"
fi
dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_dconf_gnome_screensaver_idle_delay'

# ── FIXING: Dconf Gnome Screensaver Lock Delay ──
# Rule: xccdf_org.ssgproject.content_rule_dconf_gnome_screensaver_lock_delay
# BEGIN fix (21 / 379) for 'xccdf_org.ssgproject.content_rule_dconf_gnome_screensaver_lock_delay'
###############################################################################
(>&2 echo "Remediating rule 21/379: 'xccdf_org.ssgproject.content_rule_dconf_gnome_screensaver_lock_delay'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

var_screensaver_lock_delay='5'


# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/screensaver\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
DBDIR="/etc/dconf/db/local.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*lock-delay\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)lock-delay(\s*=)/#\1lock-delay\2/g" "${SETTINGSFILES[@]}"
    fi
fi

[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/desktop/screensaver\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/desktop/screensaver]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "uint32 ${var_screensaver_lock_delay}")"
if grep -q "^\\s*lock-delay\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*lock-delay\\s*=\\s*.*/lock-delay=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/desktop/screensaver\\]|a\\lock-delay=${escaped_value}" "${DCONFFILE}"
fi
dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_dconf_gnome_screensaver_lock_delay'

# ── FIXING: Dconf Gnome Screensaver User Locks ──
# Rule: xccdf_org.ssgproject.content_rule_dconf_gnome_screensaver_user_locks
# BEGIN fix (22 / 379) for 'xccdf_org.ssgproject.content_rule_dconf_gnome_screensaver_user_locks'
###############################################################################
(>&2 echo "Remediating rule 22/379: 'xccdf_org.ssgproject.content_rule_dconf_gnome_screensaver_user_locks'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/desktop/screensaver/lock-delay$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/desktop/screensaver/lock-delay$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/desktop/screensaver/lock-delay$" /etc/dconf/db/local.d/
then
    echo "/org/gnome/desktop/screensaver/lock-delay" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
fi
dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_dconf_gnome_screensaver_user_locks'

# ── FIXING: Dconf Gnome Session Idle User Locks ──
# Rule: xccdf_org.ssgproject.content_rule_dconf_gnome_session_idle_user_locks
# BEGIN fix (23 / 379) for 'xccdf_org.ssgproject.content_rule_dconf_gnome_session_idle_user_locks'
###############################################################################
(>&2 echo "Remediating rule 23/379: 'xccdf_org.ssgproject.content_rule_dconf_gnome_session_idle_user_locks'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/desktop/session/idle-delay$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/local.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/desktop/session/idle-delay$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/desktop/session/idle-delay$" /etc/dconf/db/local.d/
then
    echo "/org/gnome/desktop/session/idle-delay" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
fi
dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_dconf_gnome_session_idle_user_locks'

# ── FIXING: Dconf Gnome Banner Enabled ──
# Rule: xccdf_org.ssgproject.content_rule_dconf_gnome_banner_enabled
# BEGIN fix (43 / 379) for 'xccdf_org.ssgproject.content_rule_dconf_gnome_banner_enabled'
###############################################################################
(>&2 echo "Remediating rule 43/379: 'xccdf_org.ssgproject.content_rule_dconf_gnome_banner_enabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm; then

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/login-screen\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|distro.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/distro.d/00-security-settings"
DBDIR="/etc/dconf/db/distro.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*banner-message-enable\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)banner-message-enable(\s*=)/#\1banner-message-enable\2/g" "${SETTINGSFILES[@]}"
    fi
fi

[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/login-screen\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/login-screen]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "true")"
if grep -q "^\\s*banner-message-enable\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*banner-message-enable\\s*=\\s*.*/banner-message-enable=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/login-screen\\]|a\\banner-message-enable=${escaped_value}" "${DCONFFILE}"
fi
dconf update
# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/login-screen/banner-message-enable$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|distro.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/distro.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/login-screen/banner-message-enable$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/login-screen/banner-message-enable$" /etc/dconf/db/distro.d/
then
    echo "/org/gnome/login-screen/banner-message-enable" >> "/etc/dconf/db/distro.d/locks/00-security-settings-lock"
fi
dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_dconf_gnome_banner_enabled'

# ── FIXING: Dconf Gnome Login Banner Text ──
# Rule: xccdf_org.ssgproject.content_rule_dconf_gnome_login_banner_text
# BEGIN fix (44 / 379) for 'xccdf_org.ssgproject.content_rule_dconf_gnome_login_banner_text'
###############################################################################
(>&2 echo "Remediating rule 44/379: 'xccdf_org.ssgproject.content_rule_dconf_gnome_login_banner_text'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q gdm; then

login_banner_text='^(Authorized[\s\n]+users[\s\n]+only\.[\s\n]+All[\s\n]+activity[\s\n]+may[\s\n]+be[\s\n]+monitored[\s\n]+and[\s\n]+reported\.|^(?!.*(\\|fedora|rhel|sle|ubuntu)).*)$'


# Multiple regexes transform the banner regex into a usable banner
# 0 - Remove anchors around the banner text
login_banner_text=$(echo "$login_banner_text" | sed 's/^\^\(.*\)\$$/\1/g')
# 1 - Keep only the first banners if there are multiple
#    (dod_banners contains the long and short banner)
login_banner_text=$(echo "$login_banner_text" | sed 's/^(\(.*\.\)|.*)$/\1/g')
# 2 - Add spaces ' '. (Transforms regex for "space or newline" into a " ")
login_banner_text=$(echo "$login_banner_text" | sed 's/\[\\s\\n\]+/ /g')
# 3 - Adds newline "tokens". (Transforms "(?:\[\\n\]+|(?:\\n)+)" into "(n)*")
login_banner_text=$(echo "$login_banner_text" | sed 's/(?:\[\\n\]+|(?:\\\\n)+)/(n)*/g')
# 4 - Remove any leftover backslash. (From any parethesis in the banner, for example).
login_banner_text=$(echo "$login_banner_text" | sed 's/\\//g')
# 5 - Removes the newline "token." (Transforms them into newline escape sequences "\n").
#    ( Needs to be done after 4, otherwise the escapce sequence will become just "n".
login_banner_text=$(echo "$login_banner_text" | sed 's/(n)\*/\\n/g')

# Check for setting in any of the DConf db directories
# If files contain ibus or distro, ignore them.
# The assignment assumes that individual filenames don't contain :
readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/login-screen\\]" "/etc/dconf/db/" \
                                | grep -v 'distro\|ibus\|distro.d' | cut -d":" -f1)
DCONFFILE="/etc/dconf/db/distro.d/00-security-settings"
DBDIR="/etc/dconf/db/distro.d"

mkdir -p "${DBDIR}"

# Comment out the configurations in databases different from the target one
if [ "${#SETTINGSFILES[@]}" -ne 0 ]
then
    if grep -q "^\\s*banner-message-text\\s*=" "${SETTINGSFILES[@]}"
    then
        
        sed -Ei "s/(^\s*)banner-message-text(\s*=)/#\1banner-message-text\2/g" "${SETTINGSFILES[@]}"
    fi
fi

[ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
if ! grep -q "\\[org/gnome/login-screen\\]" "${DCONFFILE}"
then
    printf '%s\n' "[org/gnome/login-screen]" >> ${DCONFFILE}
fi

escaped_value="$(sed -e 's/\\/\\\\/g' <<< "'${login_banner_text}'")"
if grep -q "^\\s*banner-message-text\\s*=" "${DCONFFILE}"
then
        sed -i "s/\\s*banner-message-text\\s*=\\s*.*/banner-message-text=${escaped_value}/g" "${DCONFFILE}"
    else
        sed -i "\\|\\[org/gnome/login-screen\\]|a\\banner-message-text=${escaped_value}" "${DCONFFILE}"
fi
dconf update
# Check for setting in any of the DConf db directories
LOCKFILES=$(grep -r "^/org/gnome/login-screen/banner-message-text$" "/etc/dconf/db/" \
            | grep -v 'distro\|ibus\|distro.d' | grep ":" | cut -d":" -f1)
LOCKSFOLDER="/etc/dconf/db/distro.d/locks"

mkdir -p "${LOCKSFOLDER}"

# Comment out the configurations in databases different from the target one
if [[ ! -z "${LOCKFILES}" ]]
then
    sed -i -E "s|^/org/gnome/login-screen/banner-message-text$|#&|" "${LOCKFILES[@]}"
fi

if ! grep -qr "^/org/gnome/login-screen/banner-message-text$" /etc/dconf/db/distro.d/
then
    echo "/org/gnome/login-screen/banner-message-text" >> "/etc/dconf/db/distro.d/locks/00-security-settings-lock"
fi
dconf update

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_dconf_gnome_login_banner_text'
