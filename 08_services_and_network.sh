#!/bin/bash
#
# RHEL 9 OSCAP Remediation - Services, Network & Firewall
# Description: Disable unnecessary services (avahi, rpcbind, nfs, bluetooth, autofs, telnet, ftp, etc.), enable firewalld/nftables, configure NTP/chrony, postfix, legacy trust files, GPG check, etc.
# Rules covered: 18
#
# Usage: Run as root: bash 08_services_and_network.sh
#

set -o nounset


# ── FIXING: Ensure Gpgcheck Globally Activated ──
# Rule: xccdf_org.ssgproject.content_rule_ensure_gpgcheck_globally_activated
# BEGIN fix (29 / 379) for 'xccdf_org.ssgproject.content_rule_ensure_gpgcheck_globally_activated'
###############################################################################
(>&2 echo "Remediating rule 29/379: 'xccdf_org.ssgproject.content_rule_ensure_gpgcheck_globally_activated'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q dnf; then

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^gpgcheck")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "1"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^gpgcheck\\>" "/etc/dnf/dnf.conf"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^gpgcheck\\>.*/$escaped_formatted_output/gi" "/etc/dnf/dnf.conf"
else
    if [[ -s "/etc/dnf/dnf.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/dnf/dnf.conf" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/dnf/dnf.conf"
    fi
    cce="CCE-83457-2"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "/etc/dnf/dnf.conf" >> "/etc/dnf/dnf.conf"
    printf '%s\n' "$formatted_output" >> "/etc/dnf/dnf.conf"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_ensure_gpgcheck_globally_activated'

# ── FIXING: Service Systemd-Journald Enabled ──
# Rule: xccdf_org.ssgproject.content_rule_service_systemd-journald_enabled
# BEGIN fix (111 / 379) for 'xccdf_org.ssgproject.content_rule_service_systemd-journald_enabled'
###############################################################################
(>&2 echo "Remediating rule 111/379: 'xccdf_org.ssgproject.content_rule_service_systemd-journald_enabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" unmask 'systemd-journald.service'
if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
  "$SYSTEMCTL_EXEC" start 'systemd-journald.service'
fi
"$SYSTEMCTL_EXEC" enable 'systemd-journald.service'

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_service_systemd-journald_enabled'

# ── FIXING: Socket Systemd-Journal-Remote Disabled ──
# Rule: xccdf_org.ssgproject.content_rule_socket_systemd-journal-remote_disabled
# BEGIN fix (114 / 379) for 'xccdf_org.ssgproject.content_rule_socket_systemd-journal-remote_disabled'
###############################################################################
(>&2 echo "Remediating rule 114/379: 'xccdf_org.ssgproject.content_rule_socket_systemd-journal-remote_disabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

SOCKET_NAME="systemd-journal-remote.socket"
SYSTEMCTL_EXEC='/usr/bin/systemctl'

if "$SYSTEMCTL_EXEC" -q list-unit-files --type socket | grep -q "$SOCKET_NAME"; then
    if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
      "$SYSTEMCTL_EXEC" stop "$SOCKET_NAME"
    fi
    "$SYSTEMCTL_EXEC" mask "$SOCKET_NAME"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_socket_systemd-journal-remote_disabled'

# ── FIXING: Service Firewalld Enabled ──
# Rule: xccdf_org.ssgproject.content_rule_service_firewalld_enabled
# BEGIN fix (116 / 379) for 'xccdf_org.ssgproject.content_rule_service_firewalld_enabled'
###############################################################################
(>&2 echo "Remediating rule 116/379: 'xccdf_org.ssgproject.content_rule_service_firewalld_enabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && { rpm --quiet -q firewalld; }; then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" unmask 'firewalld.service'
if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
  "$SYSTEMCTL_EXEC" start 'firewalld.service'
fi
"$SYSTEMCTL_EXEC" enable 'firewalld.service'

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_service_firewalld_enabled'

# ── FIXING: Firewalld Loopback Traffic Restricted ──
# Rule: xccdf_org.ssgproject.content_rule_firewalld_loopback_traffic_restricted
# BEGIN fix (117 / 379) for 'xccdf_org.ssgproject.content_rule_firewalld_loopback_traffic_restricted'
###############################################################################
(>&2 echo "Remediating rule 117/379: 'xccdf_org.ssgproject.content_rule_firewalld_loopback_traffic_restricted'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if ! rpm -q --quiet "firewalld" ; then
    dnf install -y "firewalld"
fi

ipv4_rule='rule family=ipv4 source address="127.0.0.1" destination not address="127.0.0.1" drop'
ipv6_rule='rule family=ipv6 source address="::1" destination not address="::1" drop'

if test "$(stat -c %d:%i /)" != "$(stat -c %d:%i /proc/1/root/.)" || [[ "$OSCAP_BOOTC_BUILD" == "YES" ]]; then
    firewall-offline-cmd --zone=trusted --add-rich-rule="${ipv4_rule}"
    firewall-offline-cmd --zone=trusted --add-rich-rule="${ipv6_rule}"
elif systemctl is-active firewalld; then
    firewall-cmd --permanent --zone=trusted --add-rich-rule="${ipv4_rule}"
    firewall-cmd --permanent --zone=trusted --add-rich-rule="${ipv6_rule}"
    firewall-cmd --reload
else
    echo "
    firewalld service is not active. Remediation aborted!
    This remediation could not be applied because it depends on firewalld service running.
    The service is not started by this remediation in order to prevent connection issues."
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_firewalld_loopback_traffic_restricted'

# ── FIXING: Firewalld Loopback Traffic Trusted ──
# Rule: xccdf_org.ssgproject.content_rule_firewalld_loopback_traffic_trusted
# BEGIN fix (118 / 379) for 'xccdf_org.ssgproject.content_rule_firewalld_loopback_traffic_trusted'
###############################################################################
(>&2 echo "Remediating rule 118/379: 'xccdf_org.ssgproject.content_rule_firewalld_loopback_traffic_trusted'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if ! rpm -q --quiet "firewalld" ; then
    dnf install -y "firewalld"
fi

if test "$(stat -c %d:%i /)" != "$(stat -c %d:%i /proc/1/root/.)" || [[ "$OSCAP_BOOTC_BUILD" == "YES" ]]; then
    firewall-offline-cmd --zone=trusted --add-interface=lo
elif systemctl is-active firewalld; then
    firewall-cmd --permanent --zone=trusted --add-interface=lo
    firewall-cmd --reload
else
    echo "
    firewalld service is not active. Remediation aborted!
    This remediation could not be applied because it depends on firewalld service running.
    The service is not started by this remediation in order to prevent connection issues."
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_firewalld_loopback_traffic_trusted'

# ── FIXING: Service Nftables Disabled ──
# Rule: xccdf_org.ssgproject.content_rule_service_nftables_disabled
# BEGIN fix (143 / 379) for 'xccdf_org.ssgproject.content_rule_service_nftables_disabled'
###############################################################################
(>&2 echo "Remediating rule 143/379: 'xccdf_org.ssgproject.content_rule_service_nftables_disabled'"); (
# Remediation is applicable only in certain platforms
if ( rpm --quiet -q firewalld && rpm --quiet -q nftables && rpm --quiet -q kernel ); then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
  "$SYSTEMCTL_EXEC" stop 'nftables.service'
fi
"$SYSTEMCTL_EXEC" disable 'nftables.service'
"$SYSTEMCTL_EXEC" mask 'nftables.service'
# Disable socket activation if we have a unit file for it
if "$SYSTEMCTL_EXEC" -q list-unit-files nftables.socket; then
    if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
      "$SYSTEMCTL_EXEC" stop 'nftables.socket'
    fi
    "$SYSTEMCTL_EXEC" mask 'nftables.socket'
fi
# The service may not be running because it has been started and failed,
# so let's reset the state so OVAL checks pass.
# Service should be 'inactive', not 'failed' after reboot though.
"$SYSTEMCTL_EXEC" reset-failed 'nftables.service' || true

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_service_nftables_disabled'

# ── FIXING: Service Bluetooth Disabled ──
# Rule: xccdf_org.ssgproject.content_rule_service_bluetooth_disabled
# BEGIN fix (148 / 379) for 'xccdf_org.ssgproject.content_rule_service_bluetooth_disabled'
###############################################################################
(>&2 echo "Remediating rule 148/379: 'xccdf_org.ssgproject.content_rule_service_bluetooth_disabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
  "$SYSTEMCTL_EXEC" stop 'bluetooth.service'
fi
"$SYSTEMCTL_EXEC" disable 'bluetooth.service'
"$SYSTEMCTL_EXEC" mask 'bluetooth.service'
# Disable socket activation if we have a unit file for it
if "$SYSTEMCTL_EXEC" -q list-unit-files bluetooth.socket; then
    if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
      "$SYSTEMCTL_EXEC" stop 'bluetooth.socket'
    fi
    "$SYSTEMCTL_EXEC" mask 'bluetooth.socket'
fi
# The service may not be running because it has been started and failed,
# so let's reset the state so OVAL checks pass.
# Service should be 'inactive', not 'failed' after reboot though.
"$SYSTEMCTL_EXEC" reset-failed 'bluetooth.service' || true

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_service_bluetooth_disabled'

# ── FIXING: Service Autofs Disabled ──
# Rule: xccdf_org.ssgproject.content_rule_service_autofs_disabled
# BEGIN fix (181 / 379) for 'xccdf_org.ssgproject.content_rule_service_autofs_disabled'
###############################################################################
(>&2 echo "Remediating rule 181/379: 'xccdf_org.ssgproject.content_rule_service_autofs_disabled'"); (
# Remediation is applicable only in certain platforms
if ( rpm --quiet -q autofs && rpm --quiet -q kernel ); then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
  "$SYSTEMCTL_EXEC" stop 'autofs.service'
fi
"$SYSTEMCTL_EXEC" disable 'autofs.service'
"$SYSTEMCTL_EXEC" mask 'autofs.service'
# Disable socket activation if we have a unit file for it
if "$SYSTEMCTL_EXEC" -q list-unit-files autofs.socket; then
    if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
      "$SYSTEMCTL_EXEC" stop 'autofs.socket'
    fi
    "$SYSTEMCTL_EXEC" mask 'autofs.socket'
fi
# The service may not be running because it has been started and failed,
# so let's reset the state so OVAL checks pass.
# Service should be 'inactive', not 'failed' after reboot though.
"$SYSTEMCTL_EXEC" reset-failed 'autofs.service' || true

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_service_autofs_disabled'

# ── FIXING: Service Avahi-Daemon Disabled ──
# Rule: xccdf_org.ssgproject.content_rule_service_avahi-daemon_disabled
# BEGIN fix (219 / 379) for 'xccdf_org.ssgproject.content_rule_service_avahi-daemon_disabled'
###############################################################################
(>&2 echo "Remediating rule 219/379: 'xccdf_org.ssgproject.content_rule_service_avahi-daemon_disabled'"); (
# Remediation is applicable only in certain platforms
if ( rpm --quiet -q avahi && rpm --quiet -q kernel ); then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
  "$SYSTEMCTL_EXEC" stop 'avahi-daemon.service'
fi
"$SYSTEMCTL_EXEC" disable 'avahi-daemon.service'
"$SYSTEMCTL_EXEC" mask 'avahi-daemon.service'
# Disable socket activation if we have a unit file for it
if "$SYSTEMCTL_EXEC" -q list-unit-files avahi-daemon.socket; then
    if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
      "$SYSTEMCTL_EXEC" stop 'avahi-daemon.socket'
    fi
    "$SYSTEMCTL_EXEC" mask 'avahi-daemon.socket'
fi
# The service may not be running because it has been started and failed,
# so let's reset the state so OVAL checks pass.
# Service should be 'inactive', not 'failed' after reboot though.
"$SYSTEMCTL_EXEC" reset-failed 'avahi-daemon.service' || true

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_service_avahi-daemon_disabled'

# ── FIXING: Service Crond Enabled ──
# Rule: xccdf_org.ssgproject.content_rule_service_crond_enabled
# BEGIN fix (221 / 379) for 'xccdf_org.ssgproject.content_rule_service_crond_enabled'
###############################################################################
(>&2 echo "Remediating rule 221/379: 'xccdf_org.ssgproject.content_rule_service_crond_enabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" unmask 'crond.service'
if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
  "$SYSTEMCTL_EXEC" start 'crond.service'
fi
"$SYSTEMCTL_EXEC" enable 'crond.service'

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_service_crond_enabled'

# ── FIXING: Has Nonlocal Mta ──
# Rule: xccdf_org.ssgproject.content_rule_has_nonlocal_mta
# BEGIN fix (258 / 379) for 'xccdf_org.ssgproject.content_rule_has_nonlocal_mta'
###############################################################################
(>&2 echo "Remediating rule 258/379: 'xccdf_org.ssgproject.content_rule_has_nonlocal_mta'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_has_nonlocal_mta' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_has_nonlocal_mta'

# ── FIXING: Postfix Network Listening Disabled ──
# Rule: xccdf_org.ssgproject.content_rule_postfix_network_listening_disabled
# BEGIN fix (259 / 379) for 'xccdf_org.ssgproject.content_rule_postfix_network_listening_disabled'
###############################################################################
(>&2 echo "Remediating rule 259/379: 'xccdf_org.ssgproject.content_rule_postfix_network_listening_disabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && { rpm --quiet -q postfix; }; then

var_postfix_inet_interfaces='loopback-only'


if [ -e "/etc/postfix/main.cf" ] ; then
    
    LC_ALL=C sed -i "/^\s*inet_interfaces\s\+=\s\+/Id" "/etc/postfix/main.cf"
else
    touch "/etc/postfix/main.cf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/postfix/main.cf"

cp "/etc/postfix/main.cf" "/etc/postfix/main.cf.bak"
# Insert at the end of the file
printf '%s\n' "inet_interfaces=$var_postfix_inet_interfaces" >> "/etc/postfix/main.cf"
# Clean up after ourselves.
rm "/etc/postfix/main.cf.bak"

systemctl restart postfix

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_postfix_network_listening_disabled'

# ── FIXING: Service Rpcbind Disabled ──
# Rule: xccdf_org.ssgproject.content_rule_service_rpcbind_disabled
# BEGIN fix (260 / 379) for 'xccdf_org.ssgproject.content_rule_service_rpcbind_disabled'
###############################################################################
(>&2 echo "Remediating rule 260/379: 'xccdf_org.ssgproject.content_rule_service_rpcbind_disabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
  "$SYSTEMCTL_EXEC" stop 'rpcbind.service'
fi
"$SYSTEMCTL_EXEC" disable 'rpcbind.service'
"$SYSTEMCTL_EXEC" mask 'rpcbind.service'
# Disable socket activation if we have a unit file for it
if "$SYSTEMCTL_EXEC" -q list-unit-files rpcbind.socket; then
    if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
      "$SYSTEMCTL_EXEC" stop 'rpcbind.socket'
    fi
    "$SYSTEMCTL_EXEC" mask 'rpcbind.socket'
fi
# The service may not be running because it has been started and failed,
# so let's reset the state so OVAL checks pass.
# Service should be 'inactive', not 'failed' after reboot though.
"$SYSTEMCTL_EXEC" reset-failed 'rpcbind.service' || true

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_service_rpcbind_disabled'

# ── FIXING: Service Nfs Disabled ──
# Rule: xccdf_org.ssgproject.content_rule_service_nfs_disabled
# BEGIN fix (261 / 379) for 'xccdf_org.ssgproject.content_rule_service_nfs_disabled'
###############################################################################
(>&2 echo "Remediating rule 261/379: 'xccdf_org.ssgproject.content_rule_service_nfs_disabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

SYSTEMCTL_EXEC='/usr/bin/systemctl'
if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
  "$SYSTEMCTL_EXEC" stop 'nfs-server.service'
fi
"$SYSTEMCTL_EXEC" disable 'nfs-server.service'
"$SYSTEMCTL_EXEC" mask 'nfs-server.service'
# Disable socket activation if we have a unit file for it
if "$SYSTEMCTL_EXEC" -q list-unit-files nfs-server.socket; then
    if [[ $("$SYSTEMCTL_EXEC" is-system-running) != "offline" ]]; then
      "$SYSTEMCTL_EXEC" stop 'nfs-server.socket'
    fi
    "$SYSTEMCTL_EXEC" mask 'nfs-server.socket'
fi
# The service may not be running because it has been started and failed,
# so let's reset the state so OVAL checks pass.
# Service should be 'inactive', not 'failed' after reboot though.
"$SYSTEMCTL_EXEC" reset-failed 'nfs-server.service' || true

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_service_nfs_disabled'

# ── FIXING: Chronyd Specify Remote Server ──
# Rule: xccdf_org.ssgproject.content_rule_chronyd_specify_remote_server
# BEGIN fix (263 / 379) for 'xccdf_org.ssgproject.content_rule_chronyd_specify_remote_server'
###############################################################################
(>&2 echo "Remediating rule 263/379: 'xccdf_org.ssgproject.content_rule_chronyd_specify_remote_server'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && { rpm --quiet -q chrony; }; then

var_multiple_time_servers='0.rhel.pool.ntp.org,1.rhel.pool.ntp.org,2.rhel.pool.ntp.org,3.rhel.pool.ntp.org'


config_file="/etc/chrony.conf"

if ! grep -q '^[[:space:]]*\(server\|pool\)[[:space:]]\+[[:graph:]]\+' "$config_file" ; then
  if ! grep -q '#[[:space:]]*server' "$config_file" ; then
    for server in $(echo "$var_multiple_time_servers" | tr ',' '\n') ; do
      printf '\nserver %s' "$server" >> "$config_file"
    done
  else
    sed -i 's/#[ \t]*server/server/g' "$config_file"
  fi
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_chronyd_specify_remote_server'

# ── FIXING: Chronyd Run As Chrony User ──
# Rule: xccdf_org.ssgproject.content_rule_chronyd_run_as_chrony_user
# BEGIN fix (264 / 379) for 'xccdf_org.ssgproject.content_rule_chronyd_run_as_chrony_user'
###############################################################################
(>&2 echo "Remediating rule 264/379: 'xccdf_org.ssgproject.content_rule_chronyd_run_as_chrony_user'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && { rpm --quiet -q chrony; }; then

if grep -q 'OPTIONS=.*' /etc/sysconfig/chronyd; then
	# trying to solve cases where the parameter after OPTIONS
	#may or may not be enclosed in quotes
	sed -i -E -e 's/\s*-u\s*\w+\s*/ /' -e 's/^([\s]*OPTIONS=["]?[^"]*)("?)/\1\2/' /etc/sysconfig/chronyd
fi

if grep -q 'OPTIONS=.*' /etc/sysconfig/chronyd; then
	# trying to solve cases where the parameter after OPTIONS
	#may or may not be enclosed in quotes
	sed -i -E -e 's/\s*-u\s*\w+\s*/ /' -e 's/^([\s]*OPTIONS=["]?[^"]*)("?)/\1 -u chrony\2/' /etc/sysconfig/chronyd
else
	echo 'OPTIONS="-u chrony"' >> /etc/sysconfig/chronyd
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_chronyd_run_as_chrony_user'

# ── FIXING: No Rsh Trust Files ──
# Rule: xccdf_org.ssgproject.content_rule_no_rsh_trust_files
# BEGIN fix (269 / 379) for 'xccdf_org.ssgproject.content_rule_no_rsh_trust_files'
###############################################################################
(>&2 echo "Remediating rule 269/379: 'xccdf_org.ssgproject.content_rule_no_rsh_trust_files'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q rsh-server; then

find /root -xdev -type f -name ".rhosts" -exec rm -f {} \;
find /home -maxdepth 2 -xdev -type f -name ".rhosts" -exec rm -f {} \;
rm -f /etc/hosts.equiv

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_no_rsh_trust_files'
