# This script is provided "as is" and has no connection or affiliation with Easy Anti-Cheat, Epic Games, their developers, or any third party.
# The sole purpose of this script is to facilitate the identification of non-compliance points based on what has been disclosed up to the date mentioned below.
# It should not be understood as a certificate of compatibility.
# For further information please see your distro documentation or EAC documentation
# Script distribuititon umder MIT license
#
# Don't forget to run 'chmod +x EAC_v2_ Requirements_Check.sh' before running =)
# This script needs root privilegies

#!/usr/bin/env bash

# Script environment
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'
BOLD='\033[1m'
clear

echo -e "${BOLD}=== REQUIREMENTS CHECKER: EAC v2 ===${NC}\n"

echo -e "This script is provided 'as is' and has no connection or affiliation with Easy Anti-Cheat, Epic Games, their developers, or any third party."
echo -e "The sole purpose of this script is to facilitate the identification of non-compliance points based on what has been disclosed up to the date mentioned below."
echo -e "It should not be understood as a certificate of compatibility."
echo -e "For further information please see your distro documentation or EAC documentation\n"
echo -e "* Known requirements as of 2026-11-06\n"

# Sudo needed
if [ "$EUID" -ne 0 ]; then
    echo -e "[ ${RED}✗${NC} ] ${BOLD}Access Denied:${NC} This script requires elevated privileges to perform validations, e.g., restricted kernel modules, efivars, and sockets."
    echo -e "Please run the script as root: ${BOLD}sudo $0${NC}\n"
    exit 1
fi

echo -e "${BOLD}--- Base System and Boot ---${NC}"

# 1. Distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release

    is_supported=false

    for os_base in $ID $ID_LIKE; do
        case "$os_base" in
            ubuntu|fedora|arch|debian|opensuse*|pop)
                is_supported=true
                break
                ;;
        esac
    done

    if [ "$is_supported" = true ]; then
        echo -e "[ ${GREEN}✓${NC} ] 1. Distribution: $PRETTY_NAME (Base Environment theoretically Accepted)"
    else
        echo -e "[ ${RED}✗${NC} ] 1. Distribution: $PRETTY_NAME (Base not homologated)"
    fi
else
    echo -e "[ ${RED}✗${NC} ] 1. Distribution: /etc/os-release file not found."
fi

# 2. Secure Boot
SB_ACTIVE=false
if command -v mokutil >/dev/null 2>&1 && mokutil --sb-state 2>/dev/null | grep -iq "enabled"; then
    SB_ACTIVE=true
elif command -v bootctl >/dev/null 2>&1 && bootctl status 2>/dev/null | grep -iq "Secure Boot: enabled"; then
    SB_ACTIVE=true
elif [ -f /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c ] && command -v hexdump >/dev/null 2>&1; then
    sb_hex=$(hexdump -v -e '/1 "%02X"' /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c 2>/dev/null | tail -c 2)
    if [ "$sb_hex" = "01" ]; then SB_ACTIVE=true; fi
fi

if [ "$SB_ACTIVE" = true ]; then
    echo -e "[ ${GREEN}✓${NC} ] 2. Secure Boot: Enabled"
else
    echo -e "[ ${RED}✗${NC} ] 2. Secure Boot: Disabled or inaccessible (Required)"
fi

# 3. TPM 2.0
if [ -c /dev/tpm0 ] || [ -c /dev/tpmrm0 ]; then
    echo -e "[ ${GREEN}✓${NC} ] 3. TPM 2.0: Hardware detected"
    TPM_ACTIVE=true
else
    echo -e "[ ${RED}✗${NC} ] 3. TPM 2.0: Not found in /dev/ (Required)"
    TPM_ACTIVE=false
fi

# 4. Measured Boot
if [ "$TPM_ACTIVE" = true ] && { [ -d /sys/kernel/security/tpm0/binary_bios_measurements ] || [ -d /sys/kernel/security/ima ]; }; then
    echo -e "[ ${GREEN}✓${NC} ] 4. Measured Boot: Active and generating logs"
else
    if [ "$TPM_ACTIVE" = true ]; then
        echo -e "[ ${YELLOW}!?${NC} ] 4. Measured Boot: TPM present, but boot logs missing (Check your bootloader/IMA configuration)"
    else
        echo -e "[ ${RED}✗${NC} ] 4. Measured Boot: Inactive (Depends on TPM 2.0)"
    fi
fi

echo -e "\n${BOLD}--- Kernel Security ---${NC}"

# 5. Kernel and Modules Signature
if [ "$SB_ACTIVE" = true ]; then
    taint_out=$(cat /proc/sys/kernel/tainted 2>/dev/null || echo 0)
    # Bit 13 (8192) = TAINT_UNSIGNED_MODULE
    if (( taint_out & 8192 )); then
        echo -e "[ ${YELLOW}!?${NC} ] 5. Signed Kernel: Kernel OK, but UNSIGNED modules are loaded (e.g., Proprietary drivers without MOK key)"
    else
        echo -e "[ ${GREEN}✓${NC} ] 5. Signed Kernel and Modules: Yes"
    fi
else
    echo -e "[ ${RED}✗${NC} ] 5. Signed Kernel: Strict validation fails if Secure Boot is disabled"
fi

# 6. IOMMU (Intel VT-d / AMD-Vi)
if [ -d /sys/class/iommu ] && [ "$(ls -A /sys/class/iommu 2>/dev/null)" ]; then
    if dmesg 2>/dev/null | grep -qi "IOMMU passthrough"; then
        echo -e "[ ${RED}✗${NC} ] 6. IOMMU: Active in BIOS, but in 'passthrough' mode (Isolation compromised, forbidden by Epic)"
    else
        echo -e "[ ${GREEN}✓${NC} ] 6. IOMMU: Enabled and in hardware isolation mode"
    fi
else
    echo -e "[ ${RED}✗${NC} ] 6. IOMMU: Disabled (Enable Intel VT-d / AMD-Vi in BIOS or remove iommu=pt from GRUB)"
fi

# 7. Kernel Lockdown
lockdown_state=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo "none")
if echo "$lockdown_state" | grep -q "\[integrity\]"; then
    echo -e "[ ${GREEN}✓${NC} ] 7. Kernel Lockdown: Enabled in [integrity] mode"
elif echo "$lockdown_state" | grep -q "\[confidentiality\]"; then
    echo -e "[ ${GREEN}✓${NC} ] 7. Kernel Lockdown: Enabled in [confidentiality] mode"
else
    echo -e "[ ${RED}✗${NC} ] 7. Kernel Lockdown: Disabled or in 'none' mode (Required to prevent RAM injection)"
fi

# 8. Kexec
if [ -f /proc/sys/kernel/kexec_load_disabled ]; then
    kexec_status=$(cat /proc/sys/kernel/kexec_load_disabled 2>/dev/null || echo 0)
    if [ "$kexec_status" = "1" ] || echo "$lockdown_state" | grep -q -E "\[integrity\]|\[confidentiality\]"; then
        echo -e "[ ${GREEN}✓${NC} ] 8. Kexec: Disabled/Locked"
    else
        echo -e "[ ${RED}✗${NC} ] 8. Kexec: Active (Incompatible, allows anti-cheat evasion)"
    fi
else
    echo -e "[ ${YELLOW}!?${NC} ] 8. Kexec: Status file unavailable"
fi

# 9. BPF LSM (eBPF)
if [ -f /sys/kernel/security/lsm ]; then
    if grep -q "bpf" /sys/kernel/security/lsm; then
        echo -e "[ ${GREEN}✓${NC} ] 9. BPF LSM: Active in kernel"
    else
        echo -e "[ ${RED}✗${NC} ] 9. BPF LSM: Inactive (Required for advanced monitoring by EAC)"
    fi
else
    echo -e "[ ${RED}✗${NC} ] 9. BPF LSM: Could not read LSM modules (Support missing in kernel?)"
fi

echo -e "\n${BOLD}--- Environment and Hardware ---${NC}"

# 10. VM (Hypervisor)
VIRT_STATUS="none"

if command -v systemd-detect-virt >/dev/null 2>&1; then
    VIRT_STATUS=$(systemd-detect-virt)
elif [ -f /sys/class/dmi/id/sys_vendor ]; then
    sys_vendor=$(cat /sys/class/dmi/id/sys_vendor | tr '[:upper:]' '[:lower:]')
    if [[ "$sys_vendor" == *"qemu"* ]] || [[ "$sys_vendor" == *"vmware"* ]] || [[ "$sys_vendor" == *"virtualbox"* ]] || [[ "$sys_vendor" == *"innotek"* ]]; then
        VIRT_STATUS="hardware_simulado"
    fi
fi

if [ "$VIRT_STATUS" = "none" ]; then
    echo -e "[ ${GREEN}✓${NC} ] 10. Virtualization: No VM detected (Bare-metal approved)"
else
    echo -e "[ ${RED}✗${NC} ] 10. Virtualization: [$VIRT_STATUS] environment detected (Imminent block by EAC)"
fi

# 11. Display Server
SESSION_TYPE="unknown"
REAL_USER=${SUDO_USER:-$USER}
REAL_UID=$(id -u "$REAL_USER" 2>/dev/null)

if command -v loginctl >/dev/null 2>&1; then
    SESSION_ID=$(loginctl list-sessions | grep " $REAL_USER " | grep "seat" | awk '{print $1}' | head -n 1)
    if [ -n "$SESSION_ID" ]; then
        SESSION_TYPE=$(loginctl show-session "$SESSION_ID" -p Type --value 2>/dev/null)
    fi
fi

if [ "$SESSION_TYPE" = "unknown" ] || [ -z "$SESSION_TYPE" ] || [ "$SESSION_TYPE" = "unspecified" ]; then
    if [ -n "$REAL_UID" ] && ls /run/user/"$REAL_UID"/wayland-* >/dev/null 2>&1; then
        SESSION_TYPE="wayland"
    elif ls /tmp/.X11-unix/X* >/dev/null 2>&1; then
        SESSION_TYPE="x11"
    fi
fi

if [ "$SESSION_TYPE" = "wayland" ]; then
    echo -e "[ ${GREEN}✓${NC} ] 11. Display Server: Wayland (Native screen/input isolation detected via socket)"
elif [ "$SESSION_TYPE" = "x11" ]; then
    echo -e "[ ${YELLOW}!?${NC} ] 11. Display Server: X11 (Vulnerable to global reading - Possible flag by Anti-Cheat)"
else
    echo -e "[ ${YELLOW}!?${NC} ] 11. Display Server: Not detected (Returned type: $SESSION_TYPE)"
fi

echo -e "\n\n"
read -n 1 -s -r -p "Press any key to exit"
clear
