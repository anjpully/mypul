#!/bin/bash
#
# RHEL 9 OSCAP Remediation - Kernel Parameters & Boot/GRUB Settings
# Description: Kernel modules, sysctl parameters, GRUB arguments, coredump, ASLR, crypto policy, etc.
# Rules covered: 45
#
# Usage: Run as root: bash 02_kernel_and_boot.sh
#

set -o nounset


# ── FIXING: Configure Crypto Policy ──
# Rule: xccdf_org.ssgproject.content_rule_configure_crypto_policy
# BEGIN fix (5 / 379) for 'xccdf_org.ssgproject.content_rule_configure_crypto_policy'
###############################################################################
(>&2 echo "Remediating rule 5/379: 'xccdf_org.ssgproject.content_rule_configure_crypto_policy'"); (

var_system_crypto_policy='DEFAULT:NO-SHA1'


stderr_of_call=$(update-crypto-policies --set ${var_system_crypto_policy} 2>&1 > /dev/null)
rc=$?

if test "$rc" = 127; then
	echo "$stderr_of_call" >&2
	echo "Make sure that the script is installed on the remediated system." >&2
	echo "See output of the 'dnf provides update-crypto-policies' command" >&2
	echo "to see what package to (re)install" >&2

	false  # end with an error code
elif test "$rc" != 0; then
	echo "Error invoking the update-crypto-policies script: $stderr_of_call" >&2
	false  # end with an error code
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_configure_crypto_policy'

# ── FIXING: Configure Ssh Crypto Policy ──
# Rule: xccdf_org.ssgproject.content_rule_configure_ssh_crypto_policy
# BEGIN fix (6 / 379) for 'xccdf_org.ssgproject.content_rule_configure_ssh_crypto_policy'
###############################################################################
(>&2 echo "Remediating rule 6/379: 'xccdf_org.ssgproject.content_rule_configure_ssh_crypto_policy'"); (

SSH_CONF="/etc/sysconfig/sshd"

sed -i "/^\s*CRYPTO_POLICY.*$/Id" $SSH_CONF

) # END fix for 'xccdf_org.ssgproject.content_rule_configure_ssh_crypto_policy'

# ── FIXING: Grub2 Password ──
# Rule: xccdf_org.ssgproject.content_rule_grub2_password
# BEGIN fix (106 / 379) for 'xccdf_org.ssgproject.content_rule_grub2_password'
###############################################################################
(>&2 echo "Remediating rule 106/379: 'xccdf_org.ssgproject.content_rule_grub2_password'"); (
(>&2 echo "FIX FOR THIS RULE 'xccdf_org.ssgproject.content_rule_grub2_password' IS MISSING!")

) # END fix for 'xccdf_org.ssgproject.content_rule_grub2_password'

# ── FIXING: Sysctl Net Ipv6 Conf All Accept Ra ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_all_accept_ra
# BEGIN fix (119 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_all_accept_ra'
###############################################################################
(>&2 echo "Remediating rule 119/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_all_accept_ra'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv6.conf.all.accept_ra from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.all.accept_ra.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.all.accept_ra" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv6_conf_all_accept_ra_value='0'


#
# Set runtime for net.ipv6.conf.all.accept_ra
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv6.conf.all.accept_ra="$sysctl_net_ipv6_conf_all_accept_ra_value"
fi

#
# If net.ipv6.conf.all.accept_ra present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv6.conf.all.accept_ra = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv6.conf.all.accept_ra")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv6_conf_all_accept_ra_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv6.conf.all.accept_ra\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv6.conf.all.accept_ra\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-84120-5"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_all_accept_ra'

# ── FIXING: Sysctl Net Ipv6 Conf All Accept Redirects ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_all_accept_redirects
# BEGIN fix (120 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_all_accept_redirects'
###############################################################################
(>&2 echo "Remediating rule 120/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_all_accept_redirects'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv6.conf.all.accept_redirects from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.all.accept_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.all.accept_redirects" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv6_conf_all_accept_redirects_value='0'


#
# Set runtime for net.ipv6.conf.all.accept_redirects
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv6.conf.all.accept_redirects="$sysctl_net_ipv6_conf_all_accept_redirects_value"
fi

#
# If net.ipv6.conf.all.accept_redirects present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv6.conf.all.accept_redirects = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv6.conf.all.accept_redirects")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv6_conf_all_accept_redirects_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv6.conf.all.accept_redirects\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv6.conf.all.accept_redirects\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-84125-4"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_all_accept_redirects'

# ── FIXING: Sysctl Net Ipv6 Conf All Accept Source Route ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_all_accept_source_route
# BEGIN fix (121 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_all_accept_source_route'
###############################################################################
(>&2 echo "Remediating rule 121/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_all_accept_source_route'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv6.conf.all.accept_source_route from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.all.accept_source_route.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.all.accept_source_route" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv6_conf_all_accept_source_route_value='0'


#
# Set runtime for net.ipv6.conf.all.accept_source_route
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv6.conf.all.accept_source_route="$sysctl_net_ipv6_conf_all_accept_source_route_value"
fi

#
# If net.ipv6.conf.all.accept_source_route present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv6.conf.all.accept_source_route = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv6.conf.all.accept_source_route")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv6_conf_all_accept_source_route_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv6.conf.all.accept_source_route\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv6.conf.all.accept_source_route\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-84131-2"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_all_accept_source_route'

# ── FIXING: Sysctl Net Ipv6 Conf All Forwarding ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_all_forwarding
# BEGIN fix (122 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_all_forwarding'
###############################################################################
(>&2 echo "Remediating rule 122/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_all_forwarding'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv6.conf.all.forwarding from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.all.forwarding.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.all.forwarding" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv6_conf_all_forwarding_value='0'


#
# Set runtime for net.ipv6.conf.all.forwarding
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv6.conf.all.forwarding="$sysctl_net_ipv6_conf_all_forwarding_value"
fi

#
# If net.ipv6.conf.all.forwarding present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv6.conf.all.forwarding = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv6.conf.all.forwarding")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv6_conf_all_forwarding_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv6.conf.all.forwarding\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv6.conf.all.forwarding\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-84114-8"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_all_forwarding'

# ── FIXING: Sysctl Net Ipv6 Conf Default Accept Ra ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_default_accept_ra
# BEGIN fix (123 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_default_accept_ra'
###############################################################################
(>&2 echo "Remediating rule 123/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_default_accept_ra'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv6.conf.default.accept_ra from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.default.accept_ra.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.default.accept_ra" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv6_conf_default_accept_ra_value='0'


#
# Set runtime for net.ipv6.conf.default.accept_ra
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv6.conf.default.accept_ra="$sysctl_net_ipv6_conf_default_accept_ra_value"
fi

#
# If net.ipv6.conf.default.accept_ra present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv6.conf.default.accept_ra = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv6.conf.default.accept_ra")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv6_conf_default_accept_ra_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv6.conf.default.accept_ra\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv6.conf.default.accept_ra\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-84124-7"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_default_accept_ra'

# ── FIXING: Sysctl Net Ipv6 Conf Default Accept Redirects ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_default_accept_redirects
# BEGIN fix (124 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_default_accept_redirects'
###############################################################################
(>&2 echo "Remediating rule 124/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_default_accept_redirects'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv6.conf.default.accept_redirects from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.default.accept_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.default.accept_redirects" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv6_conf_default_accept_redirects_value='0'


#
# Set runtime for net.ipv6.conf.default.accept_redirects
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv6.conf.default.accept_redirects="$sysctl_net_ipv6_conf_default_accept_redirects_value"
fi

#
# If net.ipv6.conf.default.accept_redirects present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv6.conf.default.accept_redirects = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv6.conf.default.accept_redirects")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv6_conf_default_accept_redirects_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv6.conf.default.accept_redirects\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv6.conf.default.accept_redirects\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-84113-0"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_default_accept_redirects'

# ── FIXING: Sysctl Net Ipv6 Conf Default Accept Source Route ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_default_accept_source_route
# BEGIN fix (125 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_default_accept_source_route'
###############################################################################
(>&2 echo "Remediating rule 125/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_default_accept_source_route'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv6.conf.default.accept_source_route from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv6.conf.default.accept_source_route.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv6.conf.default.accept_source_route" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv6_conf_default_accept_source_route_value='0'


#
# Set runtime for net.ipv6.conf.default.accept_source_route
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv6.conf.default.accept_source_route="$sysctl_net_ipv6_conf_default_accept_source_route_value"
fi

#
# If net.ipv6.conf.default.accept_source_route present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv6.conf.default.accept_source_route = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv6.conf.default.accept_source_route")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv6_conf_default_accept_source_route_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv6.conf.default.accept_source_route\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv6.conf.default.accept_source_route\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-84130-4"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv6_conf_default_accept_source_route'

# ── FIXING: Sysctl Net Ipv4 Conf All Accept Redirects ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_accept_redirects
# BEGIN fix (126 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_accept_redirects'
###############################################################################
(>&2 echo "Remediating rule 126/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_accept_redirects'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.conf.all.accept_redirects from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.all.accept_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.all.accept_redirects" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_conf_all_accept_redirects_value='0'


#
# Set runtime for net.ipv4.conf.all.accept_redirects
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv4.conf.all.accept_redirects="$sysctl_net_ipv4_conf_all_accept_redirects_value"
fi

#
# If net.ipv4.conf.all.accept_redirects present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.all.accept_redirects = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.all.accept_redirects")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_all_accept_redirects_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.all.accept_redirects\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.all.accept_redirects\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-84011-6"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_accept_redirects'

# ── FIXING: Sysctl Net Ipv4 Conf All Accept Source Route ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_accept_source_route
# BEGIN fix (127 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_accept_source_route'
###############################################################################
(>&2 echo "Remediating rule 127/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_accept_source_route'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.conf.all.accept_source_route from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.all.accept_source_route.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.all.accept_source_route" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_conf_all_accept_source_route_value='0'


#
# Set runtime for net.ipv4.conf.all.accept_source_route
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv4.conf.all.accept_source_route="$sysctl_net_ipv4_conf_all_accept_source_route_value"
fi

#
# If net.ipv4.conf.all.accept_source_route present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.all.accept_source_route = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.all.accept_source_route")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_all_accept_source_route_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.all.accept_source_route\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.all.accept_source_route\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-84001-7"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_accept_source_route'

# ── FIXING: Sysctl Net Ipv4 Conf All Log Martians ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_log_martians
# BEGIN fix (128 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_log_martians'
###############################################################################
(>&2 echo "Remediating rule 128/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_log_martians'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.conf.all.log_martians from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.all.log_martians.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.all.log_martians" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_conf_all_log_martians_value='1'


#
# Set runtime for net.ipv4.conf.all.log_martians
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv4.conf.all.log_martians="$sysctl_net_ipv4_conf_all_log_martians_value"
fi

#
# If net.ipv4.conf.all.log_martians present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.all.log_martians = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.all.log_martians")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_all_log_martians_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.all.log_martians\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.all.log_martians\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-84000-9"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_log_martians'

# ── FIXING: Sysctl Net Ipv4 Conf All Rp Filter ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_rp_filter
# BEGIN fix (129 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_rp_filter'
###############################################################################
(>&2 echo "Remediating rule 129/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_rp_filter'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.conf.all.rp_filter from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.all.rp_filter.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.all.rp_filter" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_conf_all_rp_filter_value='1'


#
# Set runtime for net.ipv4.conf.all.rp_filter
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv4.conf.all.rp_filter="$sysctl_net_ipv4_conf_all_rp_filter_value"
fi

#
# If net.ipv4.conf.all.rp_filter present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.all.rp_filter = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.all.rp_filter")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_all_rp_filter_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.all.rp_filter\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.all.rp_filter\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-84008-2"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_rp_filter'

# ── FIXING: Sysctl Net Ipv4 Conf All Secure Redirects ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_secure_redirects
# BEGIN fix (130 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_secure_redirects'
###############################################################################
(>&2 echo "Remediating rule 130/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_secure_redirects'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.conf.all.secure_redirects from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.all.secure_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.all.secure_redirects" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_conf_all_secure_redirects_value='0'


#
# Set runtime for net.ipv4.conf.all.secure_redirects
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv4.conf.all.secure_redirects="$sysctl_net_ipv4_conf_all_secure_redirects_value"
fi

#
# If net.ipv4.conf.all.secure_redirects present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.all.secure_redirects = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.all.secure_redirects")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_all_secure_redirects_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.all.secure_redirects\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.all.secure_redirects\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-84016-5"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_secure_redirects'

# ── FIXING: Sysctl Net Ipv4 Conf Default Accept Redirects ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_accept_redirects
# BEGIN fix (131 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_accept_redirects'
###############################################################################
(>&2 echo "Remediating rule 131/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_accept_redirects'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.conf.default.accept_redirects from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.accept_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.default.accept_redirects" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_conf_default_accept_redirects_value='0'


#
# Set runtime for net.ipv4.conf.default.accept_redirects
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv4.conf.default.accept_redirects="$sysctl_net_ipv4_conf_default_accept_redirects_value"
fi

#
# If net.ipv4.conf.default.accept_redirects present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.default.accept_redirects = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.default.accept_redirects")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_default_accept_redirects_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.default.accept_redirects\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.default.accept_redirects\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-84003-3"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_accept_redirects'

# ── FIXING: Sysctl Net Ipv4 Conf Default Accept Source Route ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_accept_source_route
# BEGIN fix (132 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_accept_source_route'
###############################################################################
(>&2 echo "Remediating rule 132/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_accept_source_route'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.conf.default.accept_source_route from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.accept_source_route.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.default.accept_source_route" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_conf_default_accept_source_route_value='0'


#
# Set runtime for net.ipv4.conf.default.accept_source_route
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv4.conf.default.accept_source_route="$sysctl_net_ipv4_conf_default_accept_source_route_value"
fi

#
# If net.ipv4.conf.default.accept_source_route present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.default.accept_source_route = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.default.accept_source_route")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_default_accept_source_route_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.default.accept_source_route\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.default.accept_source_route\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-84007-4"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_accept_source_route'

# ── FIXING: Sysctl Net Ipv4 Conf Default Log Martians ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_log_martians
# BEGIN fix (133 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_log_martians'
###############################################################################
(>&2 echo "Remediating rule 133/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_log_martians'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.conf.default.log_martians from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.log_martians.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.default.log_martians" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_conf_default_log_martians_value='1'


#
# Set runtime for net.ipv4.conf.default.log_martians
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv4.conf.default.log_martians="$sysctl_net_ipv4_conf_default_log_martians_value"
fi

#
# If net.ipv4.conf.default.log_martians present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.default.log_martians = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.default.log_martians")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_default_log_martians_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.default.log_martians\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.default.log_martians\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-84014-0"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_log_martians'

# ── FIXING: Sysctl Net Ipv4 Conf Default Rp Filter ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_rp_filter
# BEGIN fix (134 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_rp_filter'
###############################################################################
(>&2 echo "Remediating rule 134/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_rp_filter'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.conf.default.rp_filter from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.rp_filter.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.default.rp_filter" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_conf_default_rp_filter_value='1'


#
# Set runtime for net.ipv4.conf.default.rp_filter
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv4.conf.default.rp_filter="$sysctl_net_ipv4_conf_default_rp_filter_value"
fi

#
# If net.ipv4.conf.default.rp_filter present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.default.rp_filter = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.default.rp_filter")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_default_rp_filter_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.default.rp_filter\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.default.rp_filter\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-84009-0"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_rp_filter'

# ── FIXING: Sysctl Net Ipv4 Conf Default Secure Redirects ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_secure_redirects
# BEGIN fix (135 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_secure_redirects'
###############################################################################
(>&2 echo "Remediating rule 135/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_secure_redirects'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.conf.default.secure_redirects from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.secure_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.default.secure_redirects" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_conf_default_secure_redirects_value='0'


#
# Set runtime for net.ipv4.conf.default.secure_redirects
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv4.conf.default.secure_redirects="$sysctl_net_ipv4_conf_default_secure_redirects_value"
fi

#
# If net.ipv4.conf.default.secure_redirects present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.default.secure_redirects = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.default.secure_redirects")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_default_secure_redirects_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.default.secure_redirects\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.default.secure_redirects\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-84019-9"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_secure_redirects'

# ── FIXING: Sysctl Net Ipv4 Icmp Echo Ignore Broadcasts ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_icmp_echo_ignore_broadcasts
# BEGIN fix (136 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_icmp_echo_ignore_broadcasts'
###############################################################################
(>&2 echo "Remediating rule 136/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_icmp_echo_ignore_broadcasts'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.icmp_echo_ignore_broadcasts from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.icmp_echo_ignore_broadcasts.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.icmp_echo_ignore_broadcasts" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_icmp_echo_ignore_broadcasts_value='1'


#
# Set runtime for net.ipv4.icmp_echo_ignore_broadcasts
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv4.icmp_echo_ignore_broadcasts="$sysctl_net_ipv4_icmp_echo_ignore_broadcasts_value"
fi

#
# If net.ipv4.icmp_echo_ignore_broadcasts present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.icmp_echo_ignore_broadcasts = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.icmp_echo_ignore_broadcasts")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_icmp_echo_ignore_broadcasts_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.icmp_echo_ignore_broadcasts\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.icmp_echo_ignore_broadcasts\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-84004-1"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_icmp_echo_ignore_broadcasts'

# ── FIXING: Sysctl Net Ipv4 Icmp Ignore Bogus Error Responses ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_icmp_ignore_bogus_error_responses
# BEGIN fix (137 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_icmp_ignore_bogus_error_responses'
###############################################################################
(>&2 echo "Remediating rule 137/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_icmp_ignore_bogus_error_responses'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.icmp_ignore_bogus_error_responses from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.icmp_ignore_bogus_error_responses.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.icmp_ignore_bogus_error_responses" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_icmp_ignore_bogus_error_responses_value='1'


#
# Set runtime for net.ipv4.icmp_ignore_bogus_error_responses
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv4.icmp_ignore_bogus_error_responses="$sysctl_net_ipv4_icmp_ignore_bogus_error_responses_value"
fi

#
# If net.ipv4.icmp_ignore_bogus_error_responses present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.icmp_ignore_bogus_error_responses = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.icmp_ignore_bogus_error_responses")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_icmp_ignore_bogus_error_responses_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.icmp_ignore_bogus_error_responses\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.icmp_ignore_bogus_error_responses\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-84015-7"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_icmp_ignore_bogus_error_responses'

# ── FIXING: Sysctl Net Ipv4 Tcp Syncookies ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_tcp_syncookies
# BEGIN fix (138 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_tcp_syncookies'
###############################################################################
(>&2 echo "Remediating rule 138/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_tcp_syncookies'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.tcp_syncookies from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.tcp_syncookies.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.tcp_syncookies" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"

sysctl_net_ipv4_tcp_syncookies_value='1'


#
# Set runtime for net.ipv4.tcp_syncookies
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv4.tcp_syncookies="$sysctl_net_ipv4_tcp_syncookies_value"
fi

#
# If net.ipv4.tcp_syncookies present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.tcp_syncookies = value" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.tcp_syncookies")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_tcp_syncookies_value"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.tcp_syncookies\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.tcp_syncookies\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-84006-6"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_tcp_syncookies'

# ── FIXING: Sysctl Net Ipv4 Conf All Send Redirects ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_send_redirects
# BEGIN fix (139 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_send_redirects'
###############################################################################
(>&2 echo "Remediating rule 139/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_send_redirects'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.conf.all.send_redirects from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.all.send_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.all.send_redirects" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"


#
# Set runtime for net.ipv4.conf.all.send_redirects
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv4.conf.all.send_redirects="0"
fi

#
# If net.ipv4.conf.all.send_redirects present in /etc/sysctl.conf, change value to "0"
#	else, add "net.ipv4.conf.all.send_redirects = 0" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.all.send_redirects")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "0"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.all.send_redirects\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.all.send_redirects\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-83997-7"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_all_send_redirects'

# ── FIXING: Sysctl Net Ipv4 Conf Default Send Redirects ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_send_redirects
# BEGIN fix (140 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_send_redirects'
###############################################################################
(>&2 echo "Remediating rule 140/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_send_redirects'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.conf.default.send_redirects from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.send_redirects.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.conf.default.send_redirects" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"


#
# Set runtime for net.ipv4.conf.default.send_redirects
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv4.conf.default.send_redirects="0"
fi

#
# If net.ipv4.conf.default.send_redirects present in /etc/sysctl.conf, change value to "0"
#	else, add "net.ipv4.conf.default.send_redirects = 0" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.default.send_redirects")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "0"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.default.send_redirects\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.conf.default.send_redirects\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-83999-3"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_conf_default_send_redirects'

# ── FIXING: Sysctl Net Ipv4 Ip Forward ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_ip_forward
# BEGIN fix (141 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_ip_forward'
###############################################################################
(>&2 echo "Remediating rule 141/379: 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_ip_forward'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of net.ipv4.ip_forward from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.ip_forward.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "net.ipv4.ip_forward" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"


#
# Set runtime for net.ipv4.ip_forward
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w net.ipv4.ip_forward="0"
fi

#
# If net.ipv4.ip_forward present in /etc/sysctl.conf, change value to "0"
#	else, add "net.ipv4.ip_forward = 0" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.ip_forward")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "0"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.ip_forward\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^net.ipv4.ip_forward\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-83998-5"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_net_ipv4_ip_forward'

# ── FIXING: Kernel Module Dccp Disabled ──
# Rule: xccdf_org.ssgproject.content_rule_kernel_module_dccp_disabled
# BEGIN fix (144 / 379) for 'xccdf_org.ssgproject.content_rule_kernel_module_dccp_disabled'
###############################################################################
(>&2 echo "Remediating rule 144/379: 'xccdf_org.ssgproject.content_rule_kernel_module_dccp_disabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if LC_ALL=C grep -q -m 1 "^install dccp" /etc/modprobe.d/dccp.conf ; then
	
	sed -i 's#^install dccp.*#install dccp /bin/false#g' /etc/modprobe.d/dccp.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/dccp.conf
	echo "install dccp /bin/false" >> /etc/modprobe.d/dccp.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist dccp$" /etc/modprobe.d/dccp.conf ; then
	echo "blacklist dccp" >> /etc/modprobe.d/dccp.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_kernel_module_dccp_disabled'

# ── FIXING: Kernel Module Rds Disabled ──
# Rule: xccdf_org.ssgproject.content_rule_kernel_module_rds_disabled
# BEGIN fix (145 / 379) for 'xccdf_org.ssgproject.content_rule_kernel_module_rds_disabled'
###############################################################################
(>&2 echo "Remediating rule 145/379: 'xccdf_org.ssgproject.content_rule_kernel_module_rds_disabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if LC_ALL=C grep -q -m 1 "^install rds" /etc/modprobe.d/rds.conf ; then
	
	sed -i 's#^install rds.*#install rds /bin/false#g' /etc/modprobe.d/rds.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/rds.conf
	echo "install rds /bin/false" >> /etc/modprobe.d/rds.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist rds$" /etc/modprobe.d/rds.conf ; then
	echo "blacklist rds" >> /etc/modprobe.d/rds.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_kernel_module_rds_disabled'

# ── FIXING: Kernel Module Sctp Disabled ──
# Rule: xccdf_org.ssgproject.content_rule_kernel_module_sctp_disabled
# BEGIN fix (146 / 379) for 'xccdf_org.ssgproject.content_rule_kernel_module_sctp_disabled'
###############################################################################
(>&2 echo "Remediating rule 146/379: 'xccdf_org.ssgproject.content_rule_kernel_module_sctp_disabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if LC_ALL=C grep -q -m 1 "^install sctp" /etc/modprobe.d/sctp.conf ; then
	
	sed -i 's#^install sctp.*#install sctp /bin/false#g' /etc/modprobe.d/sctp.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/sctp.conf
	echo "install sctp /bin/false" >> /etc/modprobe.d/sctp.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist sctp$" /etc/modprobe.d/sctp.conf ; then
	echo "blacklist sctp" >> /etc/modprobe.d/sctp.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_kernel_module_sctp_disabled'

# ── FIXING: Kernel Module Tipc Disabled ──
# Rule: xccdf_org.ssgproject.content_rule_kernel_module_tipc_disabled
# BEGIN fix (147 / 379) for 'xccdf_org.ssgproject.content_rule_kernel_module_tipc_disabled'
###############################################################################
(>&2 echo "Remediating rule 147/379: 'xccdf_org.ssgproject.content_rule_kernel_module_tipc_disabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if LC_ALL=C grep -q -m 1 "^install tipc" /etc/modprobe.d/tipc.conf ; then
	
	sed -i 's#^install tipc.*#install tipc /bin/false#g' /etc/modprobe.d/tipc.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/tipc.conf
	echo "install tipc /bin/false" >> /etc/modprobe.d/tipc.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist tipc$" /etc/modprobe.d/tipc.conf ; then
	echo "blacklist tipc" >> /etc/modprobe.d/tipc.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_kernel_module_tipc_disabled'

# ── FIXING: Kernel Module Cramfs Disabled ──
# Rule: xccdf_org.ssgproject.content_rule_kernel_module_cramfs_disabled
# BEGIN fix (182 / 379) for 'xccdf_org.ssgproject.content_rule_kernel_module_cramfs_disabled'
###############################################################################
(>&2 echo "Remediating rule 182/379: 'xccdf_org.ssgproject.content_rule_kernel_module_cramfs_disabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if LC_ALL=C grep -q -m 1 "^install cramfs" /etc/modprobe.d/cramfs.conf ; then
	
	sed -i 's#^install cramfs.*#install cramfs /bin/false#g' /etc/modprobe.d/cramfs.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/cramfs.conf
	echo "install cramfs /bin/false" >> /etc/modprobe.d/cramfs.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist cramfs$" /etc/modprobe.d/cramfs.conf ; then
	echo "blacklist cramfs" >> /etc/modprobe.d/cramfs.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_kernel_module_cramfs_disabled'

# ── FIXING: Kernel Module Freevxfs Disabled ──
# Rule: xccdf_org.ssgproject.content_rule_kernel_module_freevxfs_disabled
# BEGIN fix (183 / 379) for 'xccdf_org.ssgproject.content_rule_kernel_module_freevxfs_disabled'
###############################################################################
(>&2 echo "Remediating rule 183/379: 'xccdf_org.ssgproject.content_rule_kernel_module_freevxfs_disabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if LC_ALL=C grep -q -m 1 "^install freevxfs" /etc/modprobe.d/freevxfs.conf ; then
	
	sed -i 's#^install freevxfs.*#install freevxfs /bin/false#g' /etc/modprobe.d/freevxfs.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/freevxfs.conf
	echo "install freevxfs /bin/false" >> /etc/modprobe.d/freevxfs.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist freevxfs$" /etc/modprobe.d/freevxfs.conf ; then
	echo "blacklist freevxfs" >> /etc/modprobe.d/freevxfs.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_kernel_module_freevxfs_disabled'

# ── FIXING: Kernel Module Hfs Disabled ──
# Rule: xccdf_org.ssgproject.content_rule_kernel_module_hfs_disabled
# BEGIN fix (184 / 379) for 'xccdf_org.ssgproject.content_rule_kernel_module_hfs_disabled'
###############################################################################
(>&2 echo "Remediating rule 184/379: 'xccdf_org.ssgproject.content_rule_kernel_module_hfs_disabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if LC_ALL=C grep -q -m 1 "^install hfs" /etc/modprobe.d/hfs.conf ; then
	
	sed -i 's#^install hfs.*#install hfs /bin/false#g' /etc/modprobe.d/hfs.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/hfs.conf
	echo "install hfs /bin/false" >> /etc/modprobe.d/hfs.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist hfs$" /etc/modprobe.d/hfs.conf ; then
	echo "blacklist hfs" >> /etc/modprobe.d/hfs.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_kernel_module_hfs_disabled'

# ── FIXING: Kernel Module Hfsplus Disabled ──
# Rule: xccdf_org.ssgproject.content_rule_kernel_module_hfsplus_disabled
# BEGIN fix (185 / 379) for 'xccdf_org.ssgproject.content_rule_kernel_module_hfsplus_disabled'
###############################################################################
(>&2 echo "Remediating rule 185/379: 'xccdf_org.ssgproject.content_rule_kernel_module_hfsplus_disabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if LC_ALL=C grep -q -m 1 "^install hfsplus" /etc/modprobe.d/hfsplus.conf ; then
	
	sed -i 's#^install hfsplus.*#install hfsplus /bin/false#g' /etc/modprobe.d/hfsplus.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/hfsplus.conf
	echo "install hfsplus /bin/false" >> /etc/modprobe.d/hfsplus.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist hfsplus$" /etc/modprobe.d/hfsplus.conf ; then
	echo "blacklist hfsplus" >> /etc/modprobe.d/hfsplus.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_kernel_module_hfsplus_disabled'

# ── FIXING: Kernel Module Jffs2 Disabled ──
# Rule: xccdf_org.ssgproject.content_rule_kernel_module_jffs2_disabled
# BEGIN fix (186 / 379) for 'xccdf_org.ssgproject.content_rule_kernel_module_jffs2_disabled'
###############################################################################
(>&2 echo "Remediating rule 186/379: 'xccdf_org.ssgproject.content_rule_kernel_module_jffs2_disabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if LC_ALL=C grep -q -m 1 "^install jffs2" /etc/modprobe.d/jffs2.conf ; then
	
	sed -i 's#^install jffs2.*#install jffs2 /bin/false#g' /etc/modprobe.d/jffs2.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/jffs2.conf
	echo "install jffs2 /bin/false" >> /etc/modprobe.d/jffs2.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist jffs2$" /etc/modprobe.d/jffs2.conf ; then
	echo "blacklist jffs2" >> /etc/modprobe.d/jffs2.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_kernel_module_jffs2_disabled'

# ── FIXING: Kernel Module Squashfs Disabled ──
# Rule: xccdf_org.ssgproject.content_rule_kernel_module_squashfs_disabled
# BEGIN fix (187 / 379) for 'xccdf_org.ssgproject.content_rule_kernel_module_squashfs_disabled'
###############################################################################
(>&2 echo "Remediating rule 187/379: 'xccdf_org.ssgproject.content_rule_kernel_module_squashfs_disabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if LC_ALL=C grep -q -m 1 "^install squashfs" /etc/modprobe.d/squashfs.conf ; then
	
	sed -i 's#^install squashfs.*#install squashfs /bin/false#g' /etc/modprobe.d/squashfs.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/squashfs.conf
	echo "install squashfs /bin/false" >> /etc/modprobe.d/squashfs.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist squashfs$" /etc/modprobe.d/squashfs.conf ; then
	echo "blacklist squashfs" >> /etc/modprobe.d/squashfs.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_kernel_module_squashfs_disabled'

# ── FIXING: Kernel Module Udf Disabled ──
# Rule: xccdf_org.ssgproject.content_rule_kernel_module_udf_disabled
# BEGIN fix (188 / 379) for 'xccdf_org.ssgproject.content_rule_kernel_module_udf_disabled'
###############################################################################
(>&2 echo "Remediating rule 188/379: 'xccdf_org.ssgproject.content_rule_kernel_module_udf_disabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if LC_ALL=C grep -q -m 1 "^install udf" /etc/modprobe.d/udf.conf ; then
	
	sed -i 's#^install udf.*#install udf /bin/false#g' /etc/modprobe.d/udf.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/udf.conf
	echo "install udf /bin/false" >> /etc/modprobe.d/udf.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist udf$" /etc/modprobe.d/udf.conf ; then
	echo "blacklist udf" >> /etc/modprobe.d/udf.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_kernel_module_udf_disabled'

# ── FIXING: Kernel Module Usb-Storage Disabled ──
# Rule: xccdf_org.ssgproject.content_rule_kernel_module_usb-storage_disabled
# BEGIN fix (189 / 379) for 'xccdf_org.ssgproject.content_rule_kernel_module_usb-storage_disabled'
###############################################################################
(>&2 echo "Remediating rule 189/379: 'xccdf_org.ssgproject.content_rule_kernel_module_usb-storage_disabled'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

if LC_ALL=C grep -q -m 1 "^install usb-storage" /etc/modprobe.d/usb-storage.conf ; then
	
	sed -i 's#^install usb-storage.*#install usb-storage /bin/false#g' /etc/modprobe.d/usb-storage.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/usb-storage.conf
	echo "install usb-storage /bin/false" >> /etc/modprobe.d/usb-storage.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist usb-storage$" /etc/modprobe.d/usb-storage.conf ; then
	echo "blacklist usb-storage" >> /etc/modprobe.d/usb-storage.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_kernel_module_usb-storage_disabled'

# ── FIXING: Sysctl Kernel Yama Ptrace Scope ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_kernel_yama_ptrace_scope
# BEGIN fix (209 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_kernel_yama_ptrace_scope'
###############################################################################
(>&2 echo "Remediating rule 209/379: 'xccdf_org.ssgproject.content_rule_sysctl_kernel_yama_ptrace_scope'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of kernel.yama.ptrace_scope from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*kernel.yama.ptrace_scope.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "kernel.yama.ptrace_scope" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"


#
# Set runtime for kernel.yama.ptrace_scope
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w kernel.yama.ptrace_scope="1"
fi

#
# If kernel.yama.ptrace_scope present in /etc/sysctl.conf, change value to "1"
#	else, add "kernel.yama.ptrace_scope = 1" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^kernel.yama.ptrace_scope")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "1"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^kernel.yama.ptrace_scope\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^kernel.yama.ptrace_scope\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-83965-4"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_kernel_yama_ptrace_scope'

# ── FIXING: Coredump Disable Backtraces ──
# Rule: xccdf_org.ssgproject.content_rule_coredump_disable_backtraces
# BEGIN fix (210 / 379) for 'xccdf_org.ssgproject.content_rule_coredump_disable_backtraces'
###############################################################################
(>&2 echo "Remediating rule 210/379: 'xccdf_org.ssgproject.content_rule_coredump_disable_backtraces'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q systemd; then

found=false

# set value in all files if they contain section or key
for f in $(echo -n "/etc/systemd/coredump.conf"); do
    if [ ! -e "$f" ]; then
        continue
    fi

    # find key in section and change value
    if grep -qzosP "[[:space:]]*\[Coredump\]([^\n\[]*\n+)+?[[:space:]]*ProcessSizeMax" "$f"; then

            sed -i "s/ProcessSizeMax[^(\n)]*/ProcessSizeMax=0/" "$f"

            found=true

    # find section and add key = value to it
    elif grep -qs "[[:space:]]*\[Coredump\]" "$f"; then

            sed -i "/[[:space:]]*\[Coredump\]/a ProcessSizeMax=0" "$f"

            found=true
    fi
done

# if section not in any file, append section with key = value to FIRST file in files parameter
if ! $found ; then
    file=$(echo "/etc/systemd/coredump.conf" | cut -f1 -d ' ')
    mkdir -p "$(dirname "$file")"

    echo -e "[Coredump]\nProcessSizeMax=0" >> "$file"

fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_coredump_disable_backtraces'

# ── FIXING: Coredump Disable Storage ──
# Rule: xccdf_org.ssgproject.content_rule_coredump_disable_storage
# BEGIN fix (211 / 379) for 'xccdf_org.ssgproject.content_rule_coredump_disable_storage'
###############################################################################
(>&2 echo "Remediating rule 211/379: 'xccdf_org.ssgproject.content_rule_coredump_disable_storage'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q systemd; then

found=false

# set value in all files if they contain section or key
for f in $(echo -n "/etc/systemd/coredump.conf"); do
    if [ ! -e "$f" ]; then
        continue
    fi

    # find key in section and change value
    if grep -qzosP "[[:space:]]*\[Coredump\]([^\n\[]*\n+)+?[[:space:]]*Storage" "$f"; then

            sed -i "s/Storage[^(\n)]*/Storage=none/" "$f"

            found=true

    # find section and add key = value to it
    elif grep -qs "[[:space:]]*\[Coredump\]" "$f"; then

            sed -i "/[[:space:]]*\[Coredump\]/a Storage=none" "$f"

            found=true
    fi
done

# if section not in any file, append section with key = value to FIRST file in files parameter
if ! $found ; then
    file=$(echo "/etc/systemd/coredump.conf" | cut -f1 -d ' ')
    mkdir -p "$(dirname "$file")"

    echo -e "[Coredump]\nStorage=none" >> "$file"

fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_coredump_disable_storage'

# ── FIXING: Sysctl Kernel Randomize Va Space ──
# Rule: xccdf_org.ssgproject.content_rule_sysctl_kernel_randomize_va_space
# BEGIN fix (212 / 379) for 'xccdf_org.ssgproject.content_rule_sysctl_kernel_randomize_va_space'
###############################################################################
(>&2 echo "Remediating rule 212/379: 'xccdf_org.ssgproject.content_rule_sysctl_kernel_randomize_va_space'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel; then

# Comment out any occurrences of kernel.randomize_va_space from /etc/sysctl.d/*.conf files

for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf; do


  # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
  if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

  matching_list=$(grep -P '^(?!#).*[\s]*kernel.randomize_va_space.*$' $f | uniq )
  if ! test -z "$matching_list"; then
    while IFS= read -r entry; do
      escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
      # comment out "kernel.randomize_va_space" matches to preserve user data
      sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
    done <<< "$matching_list"
  fi
done

#
# Set sysctl config file which to save the desired value
#

SYSCONFIG_FILE="/etc/sysctl.conf"


#
# Set runtime for kernel.randomize_va_space
#
if [[ "$OSCAP_BOOTC_BUILD" != "YES" ]] ; then
    /sbin/sysctl -q -n -w kernel.randomize_va_space="2"
fi

#
# If kernel.randomize_va_space present in /etc/sysctl.conf, change value to "2"
#	else, add "kernel.randomize_va_space = 2" to /etc/sysctl.conf
#

# Strip any search characters in the key arg so that the key can be replaced without
# adding any search characters to the config file.
stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^kernel.randomize_va_space")

# shellcheck disable=SC2059
printf -v formatted_output "%s = %s" "$stripped_key" "2"

# If the key exists, change it. Otherwise, add it to the config_file.
# We search for the key string followed by a word boundary (matched by \>),
# so if we search for 'setting', 'setting2' won't match.
if LC_ALL=C grep -q -m 1 -i -e "^kernel.randomize_va_space\\>" "${SYSCONFIG_FILE}"; then
    escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
    LC_ALL=C sed -i --follow-symlinks "s/^kernel.randomize_va_space\\>.*/$escaped_formatted_output/gi" "${SYSCONFIG_FILE}"
else
    if [[ -s "${SYSCONFIG_FILE}" ]] && [[ -n "$(tail -c 1 -- "${SYSCONFIG_FILE}" || true)" ]]; then
        LC_ALL=C sed -i --follow-symlinks '$a'\\ "${SYSCONFIG_FILE}"
    fi
    cce="CCE-83971-2"
    printf '# Per %s: Set %s in %s\n' "${cce}" "${formatted_output}" "${SYSCONFIG_FILE}" >> "${SYSCONFIG_FILE}"
    printf '%s\n' "$formatted_output" >> "${SYSCONFIG_FILE}"
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_sysctl_kernel_randomize_va_space'

# ── FIXING: Grub2 Enable Selinux ──
# Rule: xccdf_org.ssgproject.content_rule_grub2_enable_selinux
# BEGIN fix (215 / 379) for 'xccdf_org.ssgproject.content_rule_grub2_enable_selinux'
###############################################################################
(>&2 echo "Remediating rule 215/379: 'xccdf_org.ssgproject.content_rule_grub2_enable_selinux'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && { rpm --quiet -q grub2-common; }; then

sed -i --follow-symlinks "s/selinux=0//gI" /etc/default/grub /etc/grub2.cfg /etc/grub.d/*
sed -i --follow-symlinks "s/enforcing=0//gI" /etc/default/grub /etc/grub2.cfg /etc/grub.d/*

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_grub2_enable_selinux'

# ── FIXING: Grub2 Audit Argument ──
# Rule: xccdf_org.ssgproject.content_rule_grub2_audit_argument
# BEGIN fix (307 / 379) for 'xccdf_org.ssgproject.content_rule_grub2_audit_argument'
###############################################################################
(>&2 echo "Remediating rule 307/379: 'xccdf_org.ssgproject.content_rule_grub2_audit_argument'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && { rpm --quiet -q grub2-common; }; then

expected_value="1"


if [[ "$OSCAP_BOOTC_BUILD" == "YES" ]] ; then
    KARGS_DIR="/usr/lib/bootc/kargs.d/"
    if grep -q -E "audit" "$KARGS_DIR/*.toml" ; then
        sed -i -E "s/^(\s*kargs\s*=\s*\[.*)\"audit=[^\"]*\"(.*]\s*)/\1\"audit=$expected_value\"\2/" "$KARGS_DIR/*.toml"
    else
        echo "kargs = [\"audit=$expected_value\"]" >> "$KARGS_DIR/10-audit.toml"
    fi
else

    grubby --update-kernel=ALL --args=audit=1

fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_grub2_audit_argument'

# ── FIXING: Grub2 Audit Backlog Limit Argument ──
# Rule: xccdf_org.ssgproject.content_rule_grub2_audit_backlog_limit_argument
# BEGIN fix (308 / 379) for 'xccdf_org.ssgproject.content_rule_grub2_audit_backlog_limit_argument'
###############################################################################
(>&2 echo "Remediating rule 308/379: 'xccdf_org.ssgproject.content_rule_grub2_audit_backlog_limit_argument'"); (
# Remediation is applicable only in certain platforms
if rpm --quiet -q kernel && { rpm --quiet -q grub2-common; }; then

expected_value="8192"


if [[ "$OSCAP_BOOTC_BUILD" == "YES" ]] ; then
    KARGS_DIR="/usr/lib/bootc/kargs.d/"
    if grep -q -E "audit_backlog_limit" "$KARGS_DIR/*.toml" ; then
        sed -i -E "s/^(\s*kargs\s*=\s*\[.*)\"audit_backlog_limit=[^\"]*\"(.*]\s*)/\1\"audit_backlog_limit=$expected_value\"\2/" "$KARGS_DIR/*.toml"
    else
        echo "kargs = [\"audit_backlog_limit=$expected_value\"]" >> "$KARGS_DIR/10-audit_backlog_limit.toml"
    fi
else

    grubby --update-kernel=ALL --args=audit_backlog_limit=8192

fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi

) # END fix for 'xccdf_org.ssgproject.content_rule_grub2_audit_backlog_limit_argument'
