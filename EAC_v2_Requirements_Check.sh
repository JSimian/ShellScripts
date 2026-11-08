
#!/usr/bin/env bash

# This script is provided "as is" and has no connection or affiliation with Easy Anti-Cheat, Epic Games, their developers, or any third party.
# The sole purpose of this script is to facilitate the identification of non-compliance points based on what has been disclosed up to the date mentioned below.
# It should not be understood as a certificate of compatibility.
# For further information please see your distro documentation or EAC documentation
# Script distribution under MIT license
#
# Don't forget to run 'chmod +x EAC_v2_Requirements_Check.sh' before running =)
# This script needs root privileges

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
echo -e "Note about Item 5: Signature status is indicative only. This script does not validate"
echo -e "the Epic Games trusted keys because we doesn't know it"
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
    if [ "$sb_hex" = "01" ]; then
        SB_ACTIVE=true
    fi
fi

if [ "$SB_ACTIVE" = true ]; then
    echo -e "[ ${GREEN}✓${NC} ] 2. Secure Boot: Enabled"
else
    echo -e "[ ${RED}✗${NC} ] 2. Secure Boot: Disabled or inaccessible (Required)"
fi

# 3. TPM 2.0
TPM_ACTIVE=false

for tpm_version_file in /sys/class/tpm/tpm*/tpm_version_major; do
    if [ -r "$tpm_version_file" ]; then
        tpm_version=$(cat "$tpm_version_file" 2>/dev/null)

        if [ "$tpm_version" = "2" ]; then
            TPM_ACTIVE=true
            break
        fi
    fi
done

if [ "$TPM_ACTIVE" = true ]; then
    echo -e "[ ${GREEN}✓${NC} ] 3. TPM 2.0: Detected"
elif [ -c /dev/tpm0 ] || [ -c /dev/tpmrm0 ]; then
    echo -e "[ ${YELLOW}?${NC} ] 3. TPM: Device detected, but TPM 2.0 version could not be confirmed"
else
    echo -e "[ ${RED}✗${NC} ] 3. TPM 2.0: Not detected (Required)"
fi

# 4. Measured Boot
MEASURED_BOOT_LOG="/sys/kernel/security/tpm0/binary_bios_measurements"

if [ "$TPM_ACTIVE" = true ] && [ -r "$MEASURED_BOOT_LOG" ]; then
    log_bytes=$(dd if="$MEASURED_BOOT_LOG" bs=1 count=1 2>/dev/null | wc -c)

    if [ "$log_bytes" -gt 0 ]; then
        echo -e "[ ${GREEN}✓${NC} ] 4. Measured Boot: Firmware TPM event log accessible"
    else
        echo -e "[ ${YELLOW}?${NC} ] 4. Measured Boot: Firmware TPM event log is empty or unreadable"
    fi
else
    if [ "$TPM_ACTIVE" = true ]; then
        echo -e "[ ${YELLOW}?${NC} ] 4. Measured Boot: Firmware TPM event log not accessible"
    else
        echo -e "[ ${RED}✗${NC} ] 4. Measured Boot: TPM 2.0 not confirmed"
    fi
fi

echo -e "\n${BOLD}--- Kernel Security ---${NC}"

# 5. Kernel and Modules Signature
if [ "$SB_ACTIVE" = true ]; then
    taint_out=$(cat /proc/sys/kernel/tainted 2>/dev/null || echo 0)

    # Bit 13 (8192) = TAINT_UNSIGNED_MODULE
    if (( taint_out & 8192 )); then
        echo -e "[ ${YELLOW}?${NC} ] 5. Kernel and Modules: An unsigned module load was recorded"
    else
        echo -e "[ ${YELLOW}?${NC} ] 5. Kernel and Modules: No unsigned module load detected (Signature integrity and trusted signing keys have not been verified)"
    fi
else
    echo -e "[ ${RED}✗${NC} ] 5. Kernel and Modules: Secure Boot is disabled; signature status cannot be assumed"
fi

# 6. IOMMU (Intel VT-d / AMD-Vi)
if [ -d /sys/class/iommu ] && [ "$(ls -A /sys/class/iommu 2>/dev/null)" ]; then

    CMDLINE=$(cat /proc/cmdline 2>/dev/null)

    if dmesg 2>/dev/null | grep -qi "IOMMU passthrough" || \
       echo "$CMDLINE" | grep -Eq '(^| )(iommu=pt|iommu\.passthrough=1)( |$)'; then
        echo -e "[ ${RED}✗${NC} ] 6. IOMMU: Active in BIOS, but passthrough mode detected (Isolation may be compromised)"
    else
        echo -e "[ ${GREEN}✓${NC} ] 6. IOMMU: Enabled; no explicit passthrough configuration detected"
    fi
else
    echo -e "[ ${RED}✗${NC} ] 6. IOMMU: Disabled (Enable Intel VT-d / AMD-Vi in BIOS or remove iommu=pt from GRUB)"
fi

# 7. Kernel Lockdown
lockdown_state=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo "none")

if echo "$lockdown_state" | grep -q "\[integrity\]"; then
    echo -e "[ ${GREEN}✓${NC} ] 7. Kernel Lockdown: Enabled in [integrity] mode"
elif echo "$lockdown_state" | grep -q "\[confidentiality\]"; then
    echo -e "[ ${RED}✗${NC} ] 7. Kernel Lockdown: [confidentiality] mode detected; [integrity] is required"
else
    echo -e "[ ${RED}✗${NC} ] 7. Kernel Lockdown: Disabled or in 'none' mode (Required)"
fi

# 8. Kexec
if [ -r /proc/sys/kernel/kexec_load_disabled ]; then
    kexec_status=$(cat /proc/sys/kernel/kexec_load_disabled 2>/dev/null)

    if [ "$kexec_status" = "1" ]; then
        echo -e "[ ${GREEN}✓${NC} ] 8. Kexec: Loading disabled at runtime"
    elif [ "$kexec_status" = "0" ]; then
        echo -e "[ ${YELLOW}?${NC} ] 8. Kexec: Loading is not disabled at runtime"
    else
        echo -e "[ ${YELLOW}?${NC} ] 8. Kexec: Could not determine runtime status"
    fi
else
    echo -e "[ ${YELLOW}?${NC} ] 8. Kexec: Runtime status unavailable"
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
    echo -e "[ ${GREEN}✓${NC} ] 10. Virtualization: No VM detected (Bare-metal)"
else
    echo -e "[ ${RED}✗${NC} ] 10. Virtualization: [$VIRT_STATUS] environment detected"
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
    echo -e "[ ${GREEN}✓${NC} ] 11. Display Server: Wayland"
elif [ "$SESSION_TYPE" = "x11" ]; then
    echo -e "[ ${YELLOW}?${NC} ] 11. Display Server: X11"
else
    echo -e "[ ${YELLOW}?${NC} ] 11. Display Server: Not detected (Returned type: $SESSION_TYPE)"
fi

echo -e "\n"
read -n 1 -s -r -p "Press any key to exit"
echo -e "\n"
