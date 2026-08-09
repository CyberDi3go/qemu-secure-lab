#!/usr/bin/env bash
#
# qemu-secure-lab - hardened QEMU/KVM lab for Arch Linux
#
# Sets up a virtualisation environment for security practice: unprivileged
# QEMU, a dedicated AppArmor profile, segmented networking and internet access
# granted per machine rather than globally.
#
# Requires Arch Linux, hardware virtualisation, systemd and sudo.
#
#
# INSTALL
#
#   ./qemu-secure-lab-1.0.1-EN.sh
#
# Run it more than once; each pass picks up where the last one stopped. The
# first sets up networking, storage and QEMU deprivileging, then asks for a
# reboot, because AppArmor is enabled on the kernel command line and cannot be
# loaded at runtime. The second loads the QEMU profile in complain mode. The
# third reviews that log and switches to enforce if nothing is pending.
# Repeating the command never redoes finished work.
#
#
# INTERNET ACCESS
#
# Decided by the network assigned to the VM, from the virt-manager drop-down.
# No commands needed.
#
#   lab-open       reaches the internet with no further steps
#   lab-nat        isolated; access is granted per machine
#   lab-isolated   no outbound access of any kind
#
# For lab-nat machines, access is managed with vmnet. It applies to the MAC at
# runtime and survives host reboots:
#
#   vmnet list          status of every VM
#   vmnet on  <vm>      grant access
#   vmnet off <vm>      revoke it
#   vmnet off-all       cut everyone off
#
# Revoking access also removes name resolution.
#
#
# OTHER COMMANDS
#
#   ./qemu-secure-lab-1.0.1-EN.sh <command>
#
#   status            recorded configuration
#   verify            checks what is actually active in the kernel
#   enforce           force the AppArmor profile into enforce mode
#   complain          put the profile back into complain mode
#   uninstall         revert everything and remove the packages
#   uninstall --soft  revert configuration only
#
# uninstall never touches disks, ISOs or VM definitions.
#
#
# NETWORKS
#
#   lab-open       NAT with DHCP and DNS, direct outbound access. Filtered
#                  like lab-nat in every other respect.
#   lab-nat        NAT with DHCP and DNS, but outbound traffic and name
#                  resolution only reach authorised MACs.
#   lab-isolated   no IP, no DHCP and no host address on the segment. VMs see
#                  each other and nothing else.
#
# All three block the host LAN, tailnet, zerotier, link-local, IPv6, outbound
# mail and SMB/RPC/RDP. VMs on the same network can see each other; crossing
# from one network to another is not possible.
#
#
# KNOWN LIMITATIONS
#
#   - One AppArmor profile covers every VM. Arch builds libvirt without
#     virt-aa-helper, so there is no per-machine confinement: the profile
#     isolates from the host, not VMs from each other.
#   - VMs on the same network can see each other. Deliberate, since
#     multi-machine exercises need it.
#   - A VM can spoof an authorised VM's MAC and inherit its access. Close it
#     by adding <filterref filter='clean-traffic'/> to the interface.
#   - Bridged and macvtap networking do not go through these rules.
#   - Sharing the clipboard, a folder or USB with a VM defeats much of the
#     isolation. Those are per-machine settings and the script leaves them be.
#
# Environment variables: IFACE_NET (outbound interface), VMS_ROOT (root for
# disks and ISOs). Run as a normal user; it asks for sudo when needed.

set -euo pipefail

# --- constants --------------------------------------------------------------
SCRIPT_VERSION="1.0.1"
# Format version of /var/lib/qemu-lab/state.env, not of the script itself.
# Only bumped when a change stops being compatible with existing state.
LAB_VERSION="5"
STATE_DIR="/var/lib/qemu-lab"
STATE_FILE="$STATE_DIR/state.env"
BACKUP_DIR="$STATE_DIR/backups"
ALLOW_FILE="$STATE_DIR/inet-allow"

VMS_ROOT="${VMS_ROOT:-$HOME/VMs}"
ISO_DIR="$VMS_ROOT/ISOs"
DISK_DIR="$VMS_ROOT/QEMU"
POOL_ISOS="lab-ISOs"
POOL_DISKS="lab-disks"

NET_NAT="lab-nat"
NET_ISO="lab-isolated"
NET_FREE="lab-open"
BR_NAT="virbr-lab"
BR_ISO="virbr-iso"
BR_FREE="virbr-open"
# Resolved at runtime: see pick_subnets
NAT_SUBNET=""
BRIDGE_IP=""
FREE_SUBNET=""
FREE_IP=""
CANDIDATE_SUBNETS=(192.168.150 192.168.171 192.168.213 10.150.42 172.28.150)

PKGS_BASE=(qemu-desktop libvirt virt-manager dnsmasq iptables-nft nftables
           edk2-ovmf swtpm ufw acl apparmor)

# Untouchable: removing these would leave the system without a firewall or ACLs
PKGS_PROTECTED=(acl iptables-nft nftables ufw)
# The lab itself, the only thing 'uninstall' removes
PKGS_PURGE=(qemu-desktop libvirt virt-manager edk2-ovmf swtpm)

QEMU_PROFILE_NAME="qemu-lab.qemu-system-x86_64"
QEMU_PROFILE_PATH="/etc/apparmor.d/${QEMU_PROFILE_NAME}"
NFT_FILE="/etc/nftables.d/vmguard.nft"
LOADER="/usr/local/bin/vmguard-load"
HELPER="/usr/local/bin/vmnet"

info() { printf '\n\033[1;34m==>\033[0m %s\n' "$1"; }
ok()   { printf '    \033[1;32m[ok]\033[0m %s\n' "$1"; }
warn() { printf '    \033[1;33m[!]\033[0m %s\n' "$1"; }
bad()  { printf '    \033[1;31m[X]\033[0m %s\n' "$1"; }
die()  { printf '\n\033[1;31m[ERROR]\033[0m %s\n' "$1" >&2; exit 1; }

# --- state ------------------------------------------------------------------
ensure_dirs() {
  sudo mkdir -p "$STATE_DIR" "$BACKUP_DIR"
  sudo chmod 700 "$STATE_DIR"
}

state_set() {
  local key="$1" val="$2"
  ensure_dirs
  sudo touch "$STATE_FILE"
  sudo sed -i "/^${key}=/d" "$STATE_FILE"
  printf '%s=%q\n' "$key" "$val" | sudo tee -a "$STATE_FILE" >/dev/null
}

# Does not overwrite: records prior state so it can be rolled back later.
state_set_once() {
  local key="$1" val="$2"
  ensure_dirs
  sudo touch "$STATE_FILE"
  sudo grep -q "^${key}=" "$STATE_FILE" 2>/dev/null && return 0
  state_set "$key" "$val"
}

state_load() {
  if sudo test -f "$STATE_FILE"; then
    # shellcheck disable=SC1090
    source <(sudo cat "$STATE_FILE")
    return 0
  fi
  return 1
}

backup_file() {
  local f="$1" dest
  sudo test -f "$f" || return 0
  ensure_dirs
  dest="$BACKUP_DIR/$(printf '%s' "$f" | tr '/' '_')"
  sudo test -f "$dest" || sudo cp -a "$f" "$dest"
}

restore_file() {
  local f="$1" dest
  dest="$BACKUP_DIR/$(printf '%s' "$f" | tr '/' '_')"
  if sudo test -f "$dest"; then
    sudo cp -a "$dest" "$f"
    ok "restored $f"
  fi
}

# --- helpers ----------------------------------------------------------------
need_user() {
  [[ $EUID -eq 0 ]] && die "Do not run this with sudo. Run it as your normal user."
  command -v pacman >/dev/null || die "This is for Arch Linux only."
  sudo -v || die "sudo is required."
  ensure_dirs
}

# State written by an incompatible version describes different networks and
# rules. Mixing them leaves orphaned configuration, so we abort.
check_previous_state() {
  sudo test -f "$STATE_FILE" || return 0
  local v
  v="$(sudo grep -E '^LAB_VERSION=' "$STATE_FILE" 2>/dev/null | cut -d= -f2 | tr -d "'\"" || true)"
  [[ -z "$v" || "$v" == "5" ]] && return 0
  echo
  bad "A previous install with state format v${v} is present."
  echo
  echo "  This version uses different networks and firewall rules, and"
  echo "  mixing them would leave orphaned configuration behind."
  echo
  echo "  Uninstall the old one with the script that created it (it deletes"
  echo "  no VMs or disks), then run this one again:"
  echo "      ./<script-anterior>.sh uninstall"
  echo
  die "Aborted without changing anything."
}

# firewalld and UFW manage the same tables; with both running the rules
# override each other unpredictably.
# The Spanish edition uses different network names but the same state file,
# nft table, helper and AppArmor profile. Running both leaves duplicated
# networks and rules that fight each other.
check_other_edition() {
  local n
  for n in lab-libre lab-aislada; do
    if sudo virsh net-info "$n" &>/dev/null; then
      echo
      bad "The Spanish edition of this lab is already installed."
      echo "  Found network '$n'. The two editions share the same state file,"
      echo "  nftables table, helper and AppArmor profile, so they cannot"
      echo "  coexist."
      echo
      echo "  Uninstall it first, then run this one:"
      echo "      ./qemu-secure-lab-1.0.1-ES.sh uninstall"
      echo
      die "Aborted without changing anything."
    fi
  done
}

check_firewall() {
  if systemctl is-active --quiet firewalld 2>/dev/null; then
    echo
    bad "firewalld is running on this machine."
    echo "  This script configures UFW, and the two tools compete for the same"
    echo "  netfilter tables. Disable one of them before continuing:"
    echo "      sudo systemctl disable --now firewalld"
    echo
    die "Aborted without changing anything."
  fi
}

check_kvm() {
  if ! grep -qE '^flags[[:space:]]*:.*[[:space:]](vmx|svm)([[:space:]]|$)' /proc/cpuinfo; then
    warn "the CPU exposes neither vmx nor svm: hardware virtualisation is"
    warn "disabled in BIOS/UEFI or absent. VMs would run emulated."
  fi
}

detect_iface() {
  if [[ -z "${IFACE_NET:-}" ]]; then
    IFACE_NET="$(ip route show default 2>/dev/null \
      | grep -vE 'tailscale|virbr|zt|docker' | awk '/default/{print $5; exit}' || true)"
  fi
  [[ -n "${IFACE_NET:-}" ]] || die "Cannot detect the outbound interface. Use: IFACE_NET=xxx $0"
}

apparmor_active() {
  [[ -d /sys/kernel/security/apparmor ]] && \
  grep -qw apparmor /sys/kernel/security/lsm 2>/dev/null
}

# /boot is usually the ESP mounted with umask 0077, so without sudo the
# detection always falls through to "unknown".
detect_bootloader() {
  if sudo test -f /boot/grub/grub.cfg && command -v grub-mkconfig >/dev/null; then
    echo grub
  elif sudo test -d /boot/loader/entries && command -v bootctl >/dev/null; then
    echo systemd-boot
  elif sudo test -f /etc/kernel/cmdline && command -v mkinitcpio >/dev/null; then
    echo uki
  else
    echo desconocido
  fi
}

build_lsm() {
  local base
  if grep -qE '(^| )lsm=' /proc/cmdline; then
    base="$(tr ' ' '\n' < /proc/cmdline | grep '^lsm=' | head -1 | cut -d= -f2- || true)"
  else
    base="$(cat /sys/kernel/security/lsm 2>/dev/null || echo 'landlock,lockdown,yama,integrity,bpf')"
  fi
  if [[ ",$base," == *,apparmor,* ]]; then
    printf '%s' "$base"
  elif [[ ",$base," == *,bpf,* ]]; then
    printf '%s' "${base/bpf/apparmor,bpf}"
  else
    printf '%s,apparmor' "$base"
  fi
}

detect_qemu_bin() {
  local p
  command -v qemu-system-x86_64 2>/dev/null && return 0
  for p in /usr/bin/qemu-system-x86_64 /usr/local/bin/qemu-system-x86_64; do
    sudo test -x "$p" && { echo "$p"; return 0; }
  done
  return 1
}

list_vms() {
  command -v virsh >/dev/null || return 0
  sudo virsh list --all --name 2>/dev/null | grep -v '^$' || true
}

# --- packages and services --------------------------------------------------
step_packages() {
  info "Packages"
  local fresh=() p
  # qemu-full already includes qemu-desktop; asking for the latter with the
  # former installed confuses pacman on some setups.
  if pacman -Qq qemu-full &>/dev/null; then
    PKGS_BASE=("${PKGS_BASE[@]/qemu-desktop/qemu-full}")
    PKGS_PURGE=("${PKGS_PURGE[@]/qemu-desktop/qemu-full}")
  fi
  for p in "${PKGS_BASE[@]}"; do
    pacman -Qq "$p" &>/dev/null || fresh+=("$p")
  done
  sudo pacman -S --needed --noconfirm "${PKGS_BASE[@]}"
  state_set_once PKGS_NEW "${fresh[*]:-}"
  if ((${#fresh[@]})); then ok "installed: ${fresh[*]}"; else ok "all already present"; fi
}

step_services() {
  info "libvirt services"
  local svc_made=() s
  for s in libvirtd.service virtlogd.socket; do
    if systemctl is-enabled --quiet "$s" 2>/dev/null; then
      ok "$s already enabled"
    else
      sudo systemctl enable "$s" >/dev/null 2>&1 || true
      svc_made+=("$s")
    fi
    sudo systemctl start "$s" >/dev/null 2>&1 || true
  done
  sudo systemctl restart virtlogd.service >/dev/null 2>&1 || true

  if systemctl is-enabled --quiet apparmor.service 2>/dev/null; then
    state_set_once AA_SVC_ENABLED_BY_US 0
  else
    sudo systemctl enable apparmor.service >/dev/null 2>&1 || true
    state_set_once AA_SVC_ENABLED_BY_US 1
  fi
  state_set_once SVC_NEW "${svc_made[*]:-}"
  ok "libvirtd, virtlogd and apparmor.service enabled"
}

step_group() {
  info "libvirt group"
  if id -nG "$USER" | grep -qw libvirt; then
    ok "already a member"
    state_set_once GROUP_ADDED 0
    RELOGIN=0
  else
    sudo usermod -aG libvirt "$USER"
    state_set_once GROUP_ADDED 1
    warn "added to the group: log out and back in for it to apply"
    RELOGIN=1
  fi
}

# A fixed subnet clashes if the machine already uses it on its LAN or a VPN.
# If the lab network exists its own subnet is kept; otherwise the first
# candidate absent from both routes and local addresses is taken.
subnet_in_use() {
  local c="$1"
  ip -4 route show 2>/dev/null | grep -qE "(^| )${c//./\\.}\\." && return 0
  ip -4 addr  show 2>/dev/null | grep -qE "inet ${c//./\\.}\\."  && return 0
  return 1
}

# /24 prefix of an already defined libvirt network, empty if absent.
subnet_of_network() {
  local net="$1" actual
  sudo virsh net-info "$net" &>/dev/null || return 0
  actual="$(sudo virsh net-dumpxml "$net" 2>/dev/null \
    | sed -n "s:.*<ip address='\\([0-9.]*\\)'.*:\\1:p" | head -1 || true)"
  [[ "$actual" =~ ^([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+$ ]] || return 0
  printf '%s' "${BASH_REMATCH[1]}"
}

pick_subnets() {
  local c
  NAT_SUBNET="$(subnet_of_network "$NET_NAT")"
  FREE_SUBNET="$(subnet_of_network "$NET_FREE")"

  for c in "${CANDIDATE_SUBNETS[@]}"; do
    [[ -n "$NAT_SUBNET" && -n "$FREE_SUBNET" ]] && break
    [[ "$c" == "$NAT_SUBNET" || "$c" == "$FREE_SUBNET" ]] && continue
    subnet_in_use "$c" && continue
    if [[ -z "$NAT_SUBNET" ]]; then NAT_SUBNET="$c"; else FREE_SUBNET="$c"; fi
  done

  if [[ -z "$NAT_SUBNET" || -z "$FREE_SUBNET" ]]; then
    warn "few free subnets left; falling back to the default candidates"
    [[ -n "$NAT_SUBNET"  ]] || NAT_SUBNET="${CANDIDATE_SUBNETS[0]}"
    [[ -n "$FREE_SUBNET" ]] || FREE_SUBNET="${CANDIDATE_SUBNETS[1]}"
  fi
  BRIDGE_IP="${NAT_SUBNET}.1"
  FREE_IP="${FREE_SUBNET}.1"
}

# --- networks ---------------------------------------------------------------
step_networks() {
  info "Lab networks"
  pick_subnets
  ok "lab-nat   ${NAT_SUBNET}.0/24 (gw $BRIDGE_IP)"
  ok "lab-open ${FREE_SUBNET}.0/24 (gw $FREE_IP)"
  local nets_made=() tmp_xml

  # Our own network. libvirt's 'default' is left alone; it is still covered
  # by vmguard, which filters any virbr* interface.
  if sudo virsh net-info "$NET_NAT" &>/dev/null; then
    ok "network '$NET_NAT' already existed"
  else
    tmp_xml="$(mktemp)"
    cat > "$tmp_xml" <<EOF
<network>
  <name>$NET_NAT</name>
  <forward mode='nat'>
    <nat><port start='1024' end='65535'/></nat>
  </forward>
  <bridge name='$BR_NAT' stp='on' delay='0'/>
  <ip address='$BRIDGE_IP' netmask='255.255.255.0'>
    <dhcp><range start='${NAT_SUBNET}.100' end='${NAT_SUBNET}.200'/></dhcp>
  </ip>
</network>
EOF
    sudo virsh net-define "$tmp_xml" >/dev/null \
      || die "Could not define network $NET_NAT"
    nets_made+=("$NET_NAT")
    rm -f "$tmp_xml"
    ok "network '$NET_NAT' created ($BR_NAT, gw $BRIDGE_IP)"
  fi
  sudo virsh net-autostart "$NET_NAT" >/dev/null 2>&1 || true
  sudo virsh net-start     "$NET_NAT" >/dev/null 2>&1 || true

  # Same as lab-nat but exempt from the allowlist: for trusted VMs that need
  # internet without being authorised one by one. Every other filter stays in
  # place (no LAN, no VPN, no IPv6, no mail, no SMB).
  if sudo virsh net-info "$NET_FREE" &>/dev/null; then
    ok "network '$NET_FREE' already existed"
  else
    tmp_xml="$(mktemp)"
    cat > "$tmp_xml" <<EOF
<network>
  <name>$NET_FREE</name>
  <forward mode='nat'>
    <nat><port start='1024' end='65535'/></nat>
  </forward>
  <bridge name='$BR_FREE' stp='on' delay='0'/>
  <ip address='$FREE_IP' netmask='255.255.255.0'>
    <dhcp><range start='${FREE_SUBNET}.100' end='${FREE_SUBNET}.200'/></dhcp>
  </ip>
</network>
EOF
    sudo virsh net-define "$tmp_xml" >/dev/null \
      || die "Could not define network $NET_FREE"
    nets_made+=("$NET_FREE")
    rm -f "$tmp_xml"
    ok "network '$NET_FREE' created ($BR_FREE, gw $FREE_IP)"
  fi
  sudo virsh net-autostart "$NET_FREE" >/dev/null 2>&1 || true
  sudo virsh net-start     "$NET_FREE" >/dev/null 2>&1 || true

  # Air gap: no <forward> and no <ip>. No NAT, no dnsmasq, no host address on
  # the segment. VMs need a static IP.
  if sudo virsh net-info "$NET_ISO" &>/dev/null; then
    ok "network '$NET_ISO' already existed"
  else
    tmp_xml="$(mktemp)"
    cat > "$tmp_xml" <<EOF
<network>
  <name>$NET_ISO</name>
  <bridge name='$BR_ISO' stp='on' delay='0'/>
</network>
EOF
    if sudo virsh net-define "$tmp_xml" >/dev/null 2>&1; then
      nets_made+=("$NET_ISO")
      ok "network '$NET_ISO' created ($BR_ISO, no IP, no DHCP, air gap)"
    else
      warn "could not define '$NET_ISO'; create it by hand in virt-manager"
    fi
    rm -f "$tmp_xml"
  fi
  sudo virsh net-autostart "$NET_ISO" >/dev/null 2>&1 || true
  sudo virsh net-start     "$NET_ISO" >/dev/null 2>&1 || true

  state_set_once NETS_NEW "${nets_made[*]:-}"
  state_set BR_NAT    "$BR_NAT"
  state_set BR_ISO    "$BR_ISO"
  state_set BR_FREE   "$BR_FREE"
  state_set BRIDGE_IP "$BRIDGE_IP"
  state_set FREE_IP   "$FREE_IP"
}

# --- firewall ---------------------------------------------------------------
step_ufw() {
  info "UFW"
  if sudo ufw status 2>/dev/null | head -1 | grep -q active; then
    state_set_once UFW_WAS_ACTIVE 1
  else
    state_set_once UFW_WAS_ACTIVE 0
  fi
  backup_file /etc/default/ufw

  sudo ufw default deny incoming  >/dev/null
  sudo ufw default allow outgoing >/dev/null
  sudo ufw default deny routed    >/dev/null
  if sudo grep -q '^DEFAULT_FORWARD_POLICY=' /etc/default/ufw; then
    sudo sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="DROP"/' /etc/default/ufw
  fi
  systemctl is-enabled --quiet ufw.service 2>/dev/null \
    || sudo systemctl enable ufw.service >/dev/null 2>&1 || true
  sudo ufw --force enable >/dev/null

  # DHCP travels to broadcast, it cannot be narrowed by destination IP.
  sudo ufw allow in on "$BR_NAT" to any port 67 proto udp \
       comment 'qemu-lab DHCP' >/dev/null
  sudo ufw allow in on "$BR_NAT" to "$BRIDGE_IP" port 53 proto udp \
       comment 'qemu-lab DNS' >/dev/null
  sudo ufw allow in on "$BR_NAT" to "$BRIDGE_IP" port 53 proto tcp \
       comment 'qemu-lab DNS' >/dev/null

  # UFW opens forwarding and vmguard decides, since it runs at priority -10
  # and is evaluated first. Without this rule no VM would get out at all.
  sudo ufw route allow in on "$BR_NAT" out on "$IFACE_NET" >/dev/null 2>&1 || true

  sudo ufw allow in on "$BR_FREE" to any port 67 proto udp \
       comment 'qemu-lab DHCP libre' >/dev/null
  sudo ufw allow in on "$BR_FREE" to "$FREE_IP" port 53 proto udp \
       comment 'qemu-lab DNS libre' >/dev/null
  sudo ufw allow in on "$BR_FREE" to "$FREE_IP" port 53 proto tcp \
       comment 'qemu-lab DNS libre' >/dev/null
  sudo ufw route allow in on "$BR_FREE" out on "$IFACE_NET" >/dev/null 2>&1 || true

  state_set UFW_RULES 1
  ok "deny incoming / deny routed, DHCP and DNS limited to the bridge"
}

# --- vmguard ----------------------------------------------------------------
step_vmguard() {
  info "vmguard (VM network containment)"
  sudo mkdir -p /etc/nftables.d
  sudo tee "$NFT_FILE" > /dev/null <<EOF
# vmguard - network containment for the lab VMs
# Generated by qemu-secure-lab-1.0.1-EN.sh
# Removed with: ./qemu-secure-lab-1.0.1-EN.sh uninstall
#
# Priority -10: evaluated before UFW (0) and before libvirt's own tables. A
# drop here is final; an accept does not exempt from later rules.
#
# The vm_inet set holds the MACs allowed out, managed by vmnet on/off.

table inet vmguard
delete table inet vmguard
table inet vmguard {

    # MACs allowed out. Empty means no VM reaches the internet.
    set vm_inet {
        type ether_addr
    }

    # Ranges that are not public internet: LAN, tailnet, zerotier, link-local
    set privadas_v4 {
        type ipv4_addr
        flags interval
        elements = {
            0.0.0.0/8,
            10.0.0.0/8,
            100.64.0.0/10,
            127.0.0.0/8,
            169.254.0.0/16,
            172.16.0.0/12,
            192.0.0.0/24,
            192.168.0.0/16,
            198.18.0.0/15,
            224.0.0.0/4,
            240.0.0.0/4
        }
    }

    # ---------------------------------------------------------------- VM -> HOST
    chain vm_host {
        # The isolated bridge does not talk to the host
        iifname "$BR_ISO" counter drop

        # DHCP: broadcast destination, cannot be narrowed by IP
        udp dport 67 accept

        # The open network resolves freely: it already has outbound access
        iifname "$BR_FREE" udp dport 53 fib daddr type local accept
        iifname "$BR_FREE" tcp dport 53 fib daddr type local accept

        # On lab-nat, DNS follows the same allowlist as outbound traffic.
        # Without this, an unauthorised VM could still exfiltrate data inside
        # subdomains, because dnsmasq forwards the query upstream.
        ether saddr @vm_inet udp dport 53 fib daddr type local accept
        ether saddr @vm_inet tcp dport 53 fib daddr type local accept

        # Any other host service is out of reach
        counter drop
    }

    chain input {
        type filter hook input priority -10; policy accept;
        iifname "virbr*" jump vm_host
    }

    # -------------------------------------------------- VM -> REST OF THE WORLD
    chain vm_salida {
        # Air gap: traffic only between VMs on the same isolated bridge
        iifname "$BR_ISO" oifname "$BR_ISO" accept
        iifname "$BR_ISO" counter drop

        # Multi-machine exercises within a single bridge
        iifname "$BR_NAT" oifname "$BR_NAT" accept
        iifname "$BR_FREE" oifname "$BR_FREE" accept

        # Never hop from one VM bridge to another
        oifname "virbr*" counter drop

        # Host private ranges are off limits
        ip daddr @privadas_v4 counter drop

        # IPv6 cut entirely: the lab networks do not use it
        meta nfproto ipv6 counter drop

        # Outbound mail
        tcp dport { 25, 465, 587, 2525 } counter drop

        # Lateral movement: SMB, NetBIOS, RPC, RDP
        tcp dport { 135, 137, 138, 139, 445, 3389 } counter drop
        udp dport { 137, 138, 139, 445 } counter drop

        # Keeps the host public IP off scanning blocklists
        ct state new limit rate over 100/second burst 200 packets counter drop

        # The open network gets out without per-MAC authorisation
        iifname "$BR_FREE" accept

        # Everywhere else, outbound access depends on the allowlist
        ether saddr @vm_inet accept
        counter drop
    }

    # ------------------------------------------------------- WORLD -> VM
    chain vm_entrada {
        # Replies to what the VM itself started
        ct state established,related accept
        # Nothing outside opens connections towards a VM
        counter drop
    }

    chain forward {
        type filter hook forward priority -10; policy accept;
        iifname "virbr*" jump vm_salida
        oifname "virbr*" jump vm_entrada
    }
}
EOF

  # Loader: applies the ruleset and repopulates the authorised MACs, so the
  # grants survive a host reboot.
  sudo tee "$LOADER" > /dev/null <<EOF
#!/usr/bin/env bash
# Loads vmguard and restores per-VM outbound grants.
# Generated by qemu-secure-lab-1.0.1-EN.sh
set -euo pipefail
/usr/bin/nft -f "$NFT_FILE"
if [[ -r "$ALLOW_FILE" ]]; then
  while read -r mac _ || [[ -n "\${mac:-}" ]]; do
    [[ "\$mac" =~ ^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\$ ]] || continue
    /usr/bin/nft add element inet vmguard vm_inet "{ \$mac }" 2>/dev/null || true
  done < "$ALLOW_FILE"
fi
EOF
  sudo chmod 755 "$LOADER"

  sudo tee /etc/systemd/system/vmguard.service > /dev/null <<EOF
[Unit]
Description=Network containment for the lab VMs (vmguard)
Documentation=file://$NFT_FILE
After=network-pre.target
Before=network.target libvirtd.service
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=$LOADER
ExecStop=/usr/bin/nft delete table inet vmguard
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  sudo touch "$ALLOW_FILE"
  sudo chmod 600 "$ALLOW_FILE"
  sudo systemctl daemon-reload
  sudo systemctl enable  vmguard.service >/dev/null 2>&1 || true
  sudo systemctl restart vmguard.service
  sudo nft list table inet vmguard >/dev/null 2>&1 \
    || die "vmguard failed to load. See the error with: sudo nft -f $NFT_FILE"
  state_set VMGUARD 1
  ok "vmguard active (by default no VM reaches the internet)"
}

# --- vmnet helper -----------------------------------------------------------
step_helper() {
  info "Installing the per-VM internet control ($HELPER)"
  sudo tee "$HELPER" > /dev/null <<EOF
#!/usr/bin/env bash
# vmnet - grant or revoke a VM's internet access at runtime.
# Generated by qemu-secure-lab-1.0.1-EN.sh
#
#   vmnet on  <vm>     grant access
#   vmnet off <vm>     revoke it
#   vmnet list         status of every VM
#   vmnet off-all      cut everyone off
#
# The grant is recorded in $ALLOW_FILE and survives reboots.
set -euo pipefail

ALLOW="$ALLOW_FILE"
NET_ISO="$NET_ISO"
NET_FREE="$NET_FREE"

macs_of() {
  sudo virsh domiflist "\$1" 2>/dev/null \\
    | awk 'tolower(\$NF) ~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}\$/ {print tolower(\$NF)}'
}

nets_of() {
  sudo virsh domiflist "\$1" 2>/dev/null | awk 'tolower(\$NF) ~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}\$/ {print \$3}'
}

vm_exists() {
  sudo virsh dominfo "\$1" &>/dev/null
}

in_set() {
  sudo nft list set inet vmguard vm_inet 2>/dev/null | grep -qi "\$1"
}

case "\${1:-}" in
  on)
    vm="\${2:-}"; [[ -n "\$vm" ]] || { echo "usage: vmnet on <vm>"; exit 1; }
    vm_exists "\$vm" || { echo "No such VM '\$vm'. Try: sudo virsh list --all"; exit 1; }
    macs="\$(macs_of "\$vm" || true)"
    [[ -n "\$macs" ]] || { echo "'\$vm' has no network interface."; exit 1; }
    if nets_of "\$vm" | grep -qx "\$NET_ISO"; then
      echo "[!] '\$vm' is on network '\$NET_ISO' (air gap)."
      echo "    That network has no outbound path by design: granting does nothing."
      echo "    Switch its network interface in virt-manager."
    fi
    if nets_of "\$vm" | grep -qx "\$NET_FREE"; then
      echo "[!] '\$vm' is already on '\$NET_FREE', which gets out without a grant."
    fi
    for m in \$macs; do
      sudo nft add element inet vmguard vm_inet "{ \$m }" 2>/dev/null || true
      grep -qi "^\$m " "\$ALLOW" 2>/dev/null \\
        || echo "\$m \$vm" | sudo tee -a "\$ALLOW" >/dev/null
    done
    echo "[on]  '\$vm' now has internet access"
    ;;
  off)
    vm="\${2:-}"; [[ -n "\$vm" ]] || { echo "usage: vmnet off <vm>"; exit 1; }
    macs="\$(macs_of "\$vm" || true)"
    if [[ -z "\$macs" ]]; then
      # The VM may be gone: clean up by looking it up by name
      macs="\$(awk -v v="\$vm" '\$2==v{print \$1}' "\$ALLOW" 2>/dev/null || true)"
    fi
    [[ -n "\$macs" ]] || { echo "No MACs found for '\$vm'."; exit 1; }
    for m in \$macs; do
      sudo nft delete element inet vmguard vm_inet "{ \$m }" 2>/dev/null || true
      sudo sed -i "/^\$m /Id" "\$ALLOW" 2>/dev/null || true
    done
    echo "[off] '\$vm' no longer has internet access"
    ;;
  off-all)
    sudo nft flush set inet vmguard vm_inet 2>/dev/null || true
    sudo truncate -s 0 "\$ALLOW" 2>/dev/null || true
    echo "[off] no VM has internet access"
    ;;
  list|status|"")
    printf '%-28s %-20s %s\\n' "VM" "NETWORK" "INTERNET"
    printf '%-28s %-20s %s\\n' "---------------------------" "-------------------" "--------"
    while read -r vm; do
      [[ -n "\$vm" ]] || continue
      net="\$(nets_of "\$vm" | paste -sd, - || true)"
      state_txt="no"
      if printf '%s' "\$net" | grep -q "\$NET_FREE"; then
        state_txt="YES (open net)"
      else
        for m in \$(macs_of "\$vm" || true); do
          in_set "\$m" && state_txt="YES"
        done
      fi
      printf '%-28s %-20s %s\\n' "\$vm" "\${net:-?}" "\$state_txt"
    done < <(sudo virsh list --all --name 2>/dev/null | grep -v '^\$')
    ;;
  *)
    echo "usage: vmnet on|off <vm> | list | off-all"
    exit 1
    ;;
esac
EOF
  sudo chmod 755 "$HELPER"
  state_set HELPER 1
  ok "vmnet on <vm> / vmnet off <vm> / vmnet list"
}

# --- pools ------------------------------------------------------------------
step_pools() {
  info "Storage directories and pools"
  mkdir -p "$ISO_DIR" "$DISK_DIR"
  chmod 700 "$VMS_ROOT"
  local pools_made=()

  # libvirt refuses two pools on the same directory, and virt-manager creates
  # one just by browsing to a folder. Look up by path, not by name.
  pool_at_path() {
    local path="$1" p t
    while read -r p; do
      [[ -n "$p" ]] || continue
      t="$(sudo virsh pool-dumpxml "$p" 2>/dev/null \
           | sed -n 's:.*<path>\(.*\)</path>.*:\1:p' | head -1 || true)"
      if [[ "$t" == "$path" ]]; then echo "$p"; return 0; fi
    done < <(sudo virsh pool-list --all --name 2>/dev/null | grep -v '^$' || true)
    return 0
  }

  add_pool() {
    local name="$1" path="$2" other
    other="$(pool_at_path "$path")"
    if [[ -n "$other" && "$other" != "$name" ]]; then
      warn "a pool ('$other') already points at $path"
      warn "reusing it instead of creating '$name' (libvirt allows no duplicates)"
      sudo virsh pool-autostart "$other" >/dev/null 2>&1 || true
      sudo virsh pool-start     "$other" >/dev/null 2>&1 || true
      return 0
    fi
    if sudo virsh pool-info "$name" &>/dev/null; then
      ok "pool '$name' already existed"
    else
      sudo virsh pool-define-as "$name" dir --target "$path" >/dev/null
      sudo virsh pool-autostart "$name" >/dev/null
      sudo virsh pool-start     "$name" >/dev/null
      pools_made+=("$name")
      ok "pool '$name' -> $path"
    fi
  }
  add_pool "$POOL_ISOS"   "$ISO_DIR"   || warn "could not prepare the ISO pool (continuing)"
  add_pool "$POOL_DISKS" "$DISK_DIR"  || warn "could not prepare the disk pool (continuing)"
  state_set_once POOLS_NEW "${pools_made[*]:-}"
}

# --- unprivileged QEMU ------------------------------------------------------
# Left alone, libvirt runs system-session VMs as root:root. Arch creates the
# libvirt-qemu account but leaves the directives commented out.
step_deprivilege() {
  info "Dropping root from QEMU"
  local QCONF=/etc/libvirt/qemu.conf
  sudo test -f "$QCONF" || { warn "$QCONF not found; skipping this step"; return 0; }

  if sudo grep -qE '^(user|group)[[:space:]]*=' "$QCONF"; then
    ok "user/group were already active in qemu.conf"
  else
    backup_file "$QCONF"
    # Only the real directives: no indentation, no trailing comment.
    sudo sed -i -E '/^#(user|group|dynamic_ownership)[[:space:]]*=[^#]*$/ s/^#//' "$QCONF"
    state_set_once QCONF_MODIFIED 1
  fi

  # Filters the syscalls QEMU may ask of the host kernel
  if ! sudo grep -qE '^seccomp_sandbox[[:space:]]*=' "$QCONF"; then
    backup_file "$QCONF"
    echo 'seccomp_sandbox = 1' | sudo tee -a "$QCONF" >/dev/null
    state_set_once QCONF_MODIFIED 1
    ok "seccomp_sandbox enabled"
  fi

  local QUSER QGROUP
  QUSER="$(sudo grep -E '^user[[:space:]]*=' "$QCONF" | head -1 \
           | sed -E 's/^user[[:space:]]*=[[:space:]]*"?([^"[:space:]]*)"?.*/\1/' || true)"
  QGROUP="$(sudo grep -E '^group[[:space:]]*=' "$QCONF" | head -1 \
           | sed -E 's/^group[[:space:]]*=[[:space:]]*"?([^"[:space:]]*)"?.*/\1/' || true)"

  if [[ -z "$QUSER" || -z "$QGROUP" ]] || ! id -u "$QUSER" &>/dev/null; then
    warn "no valid user/group in $QCONF. Uncomment user and group by hand."
    return 0
  fi
  state_set QEMU_USER  "$QUSER"
  state_set QEMU_GROUP "$QGROUP"

  # Traverse only (--x, no listing) on intermediate directories; effective
  # access limited to disks and ISOs.
  if command -v setfacl >/dev/null; then
    sudo setfacl    -m "u:${QUSER}:--x" "$HOME"                   2>/dev/null || true
    sudo setfacl    -m "u:${QUSER}:--x" "$VMS_ROOT"               2>/dev/null || true
    sudo setfacl -R -m "u:${QUSER}:rwx" "$ISO_DIR" "$DISK_DIR"    2>/dev/null || true
    sudo setfacl -R -d -m "u:${QUSER}:rwx" "$ISO_DIR" "$DISK_DIR" 2>/dev/null || true
    state_set ACL_APPLIED 1
    ok "ACLs: '$QUSER' sees only your disks and ISOs, nothing else in HOME"
  else
    warn "setfacl missing; without ACLs the VMs cannot open their disks"
  fi

  if sudo systemctl restart libvirtd.service && systemctl is-active --quiet libvirtd.service; then
    ok "QEMU will run as $QUSER:$QGROUP (no longer root)"
    state_set QEMU_USER_HARDENED 1
  else
    warn "libvirtd will not start like this -> reverting qemu.conf"
    restore_file "$QCONF"
    sudo systemctl restart libvirtd.service || true
    state_set QEMU_USER_HARDENED 0
  fi
}

# --- AppArmor: kernel command line ------------------------------------------
step_apparmor_kernel() {
  apparmor_active && return 0
  info "Preparing AppArmor on the kernel command line"
  local lsm_str boot_loader
  lsm_str="$(build_lsm)"
  boot_loader="$(detect_bootloader)"
  state_set BOOTLOADER "$boot_loader"
  case "$boot_loader" in
    grub)         cmdline_grub   "$lsm_str" ;;
    systemd-boot) cmdline_sdboot "$lsm_str" ;;
    uki)          cmdline_uki    "$lsm_str" ;;
    *) warn "bootloader not recognised; add this by hand: lsm=$lsm_str" ;;
  esac
}

cmdline_grub() {
  local lsm_str="$1" line val newline
  backup_file /etc/default/grub
  line="$(grep -E '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub | head -1 || true)"
  if [[ -z "$line" ]]; then
    printf 'GRUB_CMDLINE_LINUX_DEFAULT="lsm=%s"\n' "$lsm_str" | sudo tee -a /etc/default/grub >/dev/null
    state_set_once GRUB_CMDLINE_ORIG ""
  else
    state_set_once GRUB_CMDLINE_ORIG "$line"
    val="${line#GRUB_CMDLINE_LINUX_DEFAULT=}"
    val="${val%\"}"; val="${val#\"}"
    val="$(printf '%s' "$val" | sed -E 's/(^| )lsm=[^ ]*//g' | tr -s ' ' | sed -E 's/^ | $//g')"
    newline="GRUB_CMDLINE_LINUX_DEFAULT=\"${val:+$val }lsm=$lsm_str\""
    awk -v new="$newline" '
      /^GRUB_CMDLINE_LINUX_DEFAULT=/ && !d { print new; d=1; next } { print }
    ' /etc/default/grub | sudo tee /etc/default/grub.lab >/dev/null
    sudo mv /etc/default/grub.lab /etc/default/grub
  fi
  state_set GRUB_MODIFIED 1
  sudo grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1 \
    || die "grub-mkconfig failed. Check /etc/default/grub"
  ok "GRUB updated with lsm=$lsm_str"
}

cmdline_sdboot() {
  local lsm_str="$1" f
  ensure_dirs
  sudo test -f "$BACKUP_DIR/loader-entries.tar" \
    || sudo tar -cf "$BACKUP_DIR/loader-entries.tar" -C /boot/loader entries
  for f in /boot/loader/entries/*.conf; do
    [[ -e "$f" ]] || continue
    sudo sed -i -E "/^options /{s/(^| )lsm=[^ ]*//g; s/\$/ lsm=$lsm_str/}" "$f"
  done
  state_set SDBOOT_MODIFIED 1
  ok "systemd-boot entries updated with lsm=$lsm_str"
}

cmdline_uki() {
  local lsm_str="$1"
  backup_file /etc/kernel/cmdline
  sudo sed -i -E "s/(^| )lsm=[^ ]*//g; s/\$/ lsm=$lsm_str/" /etc/kernel/cmdline
  state_set UKI_MODIFIED 1
  sudo mkinitcpio -P >/dev/null 2>&1 || warn "mkinitcpio failed; regenerate the UKI by hand"
  ok "/etc/kernel/cmdline updated with lsm=$lsm_str"
}

# --- QEMU AppArmor profile --------------------------------------------------
# AppArmor confines by executable path, so a profile on
# /usr/bin/qemu-system-x86_64 covers every VM without needing support in
# libvirt. Arch builds it with -Dapparmor=disabled, so there is no
# virt-aa-helper and no per-machine confinement: one profile isolates from the
# host, not VMs from each other.
install_qemu_profile() {
  local QEMU_BIN d_dir i_dir
  QEMU_BIN="$(detect_qemu_bin)" || die "qemu-system-x86_64 not found"
  d_dir="$DISK_DIR"; i_dir="$ISO_DIR"

  info "QEMU AppArmor profile (complain mode)"
  backup_file "$QEMU_PROFILE_PATH"
  sudo tee "$QEMU_PROFILE_PATH" > /dev/null <<PROFILE
# AppArmor profile shared by every VM.
# Generated by qemu-secure-lab-1.0.1-EN.sh
#
# Review the log:
#   sudo journalctl -k --since '-2 hours' \\
#     | grep -E 'apparmor="(DENIED|ALLOWED)"' | grep qemu-lab
#
# Put it back into complain mode:
#   ./qemu-secure-lab-1.0.1-EN.sh complain

#include <tunables/global>

profile qemu-lab-qemu ${QEMU_BIN} flags=(attach_disconnected,complain) {
  #include <abstractions/base>

  capability chown,
  capability dac_override,
  capability dac_read_search,
  capability fowner,
  capability fsetid,
  capability ipc_lock,
  capability kill,
  capability mknod,
  capability net_bind_service,
  capability net_raw,
  capability setgid,
  capability setuid,
  capability sys_chroot,
  capability sys_resource,

  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,
  network netlink raw,
  network unix stream,
  network unix dgram,

  deny ptrace (read, trace) peer=unconfined,

  ${QEMU_BIN} mr,
  /usr/{lib,lib64}/qemu/** mr,
  /usr/share/qemu/** r,
  /usr/share/seabios/** r,
  /usr/share/edk2*/** r,
  /usr/share/OVMF/** r,
  /usr/share/swtpm/** r,

  /dev/kvm rw,
  /dev/net/tun rw,
  /dev/vhost-net rw,
  /dev/vhost-vsock rw,
  /dev/rtc0 r,
  /dev/hpet r,
  /dev/urandom r,
  /dev/random r,
  /dev/null rw,
  /dev/zero rw,
  /dev/ptmx rw,
  /dev/pts/* rw,
  /dev/vfio/** rw,

  # USB passthrough (USB Redirector / USB Host Device in virt-manager).
  # Without this QEMU cannot enumerate or open the device even though
  # libvirt has already handed it ownership of the node under /dev.
  /dev/ r,
  /dev/bus/ r,
  /dev/bus/usb/ r,
  /dev/bus/usb/** rw,
  /sys/bus/ r,
  /sys/bus/usb/devices/ r,
  /sys/class/ r,
  /sys/devices/**/usb*/** r,

  /var/lib/libvirt/qemu/** rwk,
  /var/lib/libvirt/images/** rwk,
  /var/lib/swtpm-localca/** r,
  /var/cache/libvirt/qemu/** rwk,
  /var/log/libvirt/qemu/** w,
  /var/run/libvirt/** rw,
  /run/libvirt/** rw,

  /proc/sys/vm/overcommit_memory r,
  /proc/sys/vm/max_map_count r,
  /proc/sys/kernel/yama/ptrace_scope r,
  /sys/devices/system/cpu/** r,
  /sys/devices/system/node/ r,
  /sys/devices/system/node/** r,
  /sys/module/kvm*/** r,
  /sys/module/vhost/parameters/** r,
  /sys/firmware/acpi/** r,
  /etc/libnl/classid r,
  /etc/sasl2/qemu.conf r,
  owner @{PROC}/@{pid}/status r,
  owner @{PROC}/@{pid}/task/*/comm rw,

  # The only disk and ISO paths reachable inside the home directory
  owner ${d_dir}/*.qcow2 rwk,
  owner ${d_dir}/*.img rwk,
  owner ${d_dir}/*.raw rwk,
  # k is the lock permission. QEMU locks the CD-ROM too despite mounting it
  # read-only; without it, it fails with "Failed to lock byte 100".
  owner ${i_dir}/*.iso rk,
}
PROFILE

  sudo apparmor_parser -r "$QEMU_PROFILE_PATH" \
    || die "the profile will not load. Check the syntax in $QEMU_PROFILE_PATH"
  state_set QEMU_PROFILE_INSTALLED 1
  state_set QEMU_PROFILE_ENFORCED 0
  stamp_complain
  ok "profile loaded in COMPLAIN mode (logging only, not blocking yet)"
}

# The profile file mentions "complain" in its header, so grepping for that
# word gives false positives. What the kernel has loaded wins; the file is
# only the fallback.
profile_in_complain() {
  if sudo test -r /sys/kernel/security/apparmor/profiles; then
    sudo grep -qE '^qemu-lab-qemu \(complain\)' /sys/kernel/security/apparmor/profiles && return 0
    sudo grep -qE '^qemu-lab-qemu \(enforce\)'  /sys/kernel/security/apparmor/profiles && return 1
  fi
  sudo grep -q 'flags=(attach_disconnected,complain)' "$QEMU_PROFILE_PATH" 2>/dev/null
}

# Marks how far back to review the log. Unbounded, it drags in entries from
# earlier revisions of the profile that are already fixed.
stamp_complain() {
  state_set AA_SINCE "$(date '+%Y-%m-%d %H:%M:%S')"
}

# In complain mode AppArmor logs ALLOWED, not DENIED: it records what it
# would have blocked. Both labels must be matched or the review comes up empty.
log_entries() {
  local since
  since="$(sudo grep -E '^AA_SINCE=' "$STATE_FILE" 2>/dev/null \
           | cut -d= -f2- | tr -d "'\"" || true)"
  [[ -n "$since" ]] || since="-2 days"
  sudo journalctl -k --since "$since" 2>/dev/null \
    | grep -E 'apparmor="(DENIED|ALLOWED)"' | grep -i 'qemu-lab' || true
}

switch_to_enforce() {
  sudo test -f "$QEMU_PROFILE_PATH" || die "no profile installed. Run: $0"
  if ! profile_in_complain; then
    ok "the profile was already enforcing"
    return 0
  fi
  sudo sed -i 's/flags=(attach_disconnected,complain)/flags=(attach_disconnected)/' "$QEMU_PROFILE_PATH"
  sudo apparmor_parser -r "$QEMU_PROFILE_PATH" || die "the profile failed to reload"
  state_set QEMU_PROFILE_ENFORCED 1
  ok "QEMU profile now ENFORCING"
}

switch_to_complain() {
  sudo test -f "$QEMU_PROFILE_PATH" || die "no profile installed"
  if profile_in_complain; then
    ok "the profile was already in complain mode"
    return 0
  fi
  sudo sed -i 's/flags=(attach_disconnected)/flags=(attach_disconnected,complain)/' "$QEMU_PROFILE_PATH"
  sudo apparmor_parser -r "$QEMU_PROFILE_PATH" || die "the profile failed to reload"
  state_set QEMU_PROFILE_ENFORCED 0
  stamp_complain
  ok "profile back in COMPLAIN mode (logging only, not blocking)"
}

# --- single flow ------------------------------------------------------------
cmd_auto() {
  need_user
  check_previous_state
  state_set LAB_VERSION "$LAB_VERSION"

  if grep -qE '(^| )mitigations=off( |$)' /proc/cmdline 2>/dev/null; then
    warn "mitigations=off is on your kernel command line: a bad idea with VMs"
  fi

  check_other_edition
  check_firewall
  check_kvm
  detect_iface
  state_set LAB_USER  "$USER"
  state_set IFACE_NET "$IFACE_NET"
  state_set VMS_ROOT  "$VMS_ROOT"

  local vm_list; vm_list="$(list_vms)"
  if [[ -n "$vm_list" ]]; then
    info "VMs already defined (left untouched)"
    echo "$vm_list" | sed 's/^/    - /'
  fi

  RELOGIN=0
  step_packages
  step_services
  step_group
  step_networks
  step_ufw
  step_vmguard
  step_helper
  step_pools
  step_deprivilege

  # AppArmor: the flow forks depending on whether the LSM is active
  if ! apparmor_active; then
    step_apparmor_kernel
    banner_reboot
    return 0
  fi

  ok "AppArmor active in the kernel"

  if ! sudo test -f "$QEMU_PROFILE_PATH"; then
    install_qemu_profile
    banner_try
    return 0
  fi

  if profile_in_complain; then
    local entries
    entries="$(log_entries)"
    if [[ -z "$entries" ]]; then
      if [[ -z "$vm_list" ]]; then
        banner_try
        warn "no VM defined yet: create one and run me again"
        return 0
      fi
      info "Reviewing the AppArmor log"
      ok "no denials: switching the profile to enforce"
      switch_to_enforce
    else
      info "Reviewing the AppArmor log"
      warn "denials on record; NOT switching to enforce yet:"
      echo "$entries" | tail -20 | sed 's/^/      /'
      echo
      echo "  Each line is something the profile would block. If they are"
      echo "  legitimate paths of yours, add them at the end of"
      echo "  $QEMU_PROFILE_PATH and run this again."
      echo "  To switch to enforce regardless:  $0 enforce"
      return 0
    fi
  fi

  banner_done
}

banner_reboot() {
  cat <<EOF

========================================================================
  FIRST STAGE DONE

  In place: networks, vmguard, UFW, pools and QEMU without root.

  AppArmor is still missing, and that needs a reboot: the kernel LSM
  cannot be switched on at runtime.

      sudo reboot
      $0

  Same command. It detects what is already done and carries on.

========================================================================
EOF
  [[ "${RELOGIN:-0}" == "1" ]] && warn "the reboot also sorts out the libvirt group membership"
  echo
}

banner_try() {
  cat <<EOF

========================================================================
  ALMOST THERE

  The AppArmor profile is in COMPLAIN mode: it records what it would
  block, but blocks nothing yet. That is deliberate. Switching to enforce
  without having watched a real VM run breaks things at the worst moment.

  NOW:
    1. Create or start a VM and use it for a while (boot, network, disk, USB)
    2. Run again:   $0

  If the log comes back clean, the script switches to enforce by itself.

========================================================================
EOF
}

banner_done() {
  info "Final state"
  echo
  echo "--- Networks ---";   sudo virsh net-list --all
  echo "--- Internet per VM ---"; sudo "$HELPER" list 2>/dev/null || true

  cat <<EOF

========================================================================
  LAB COMPLETE AND ENFORCING

  ISOs:   $ISO_DIR      (pool '$POOL_ISOS')
  Disks:  $DISK_DIR      (pool '$POOL_DISKS')

  PICK THE NETWORK IN VIRT-MANAGER, ON EACH VM's NIC

    $NET_FREE      reaches the internet directly. Everyday work.
    $NET_NAT       same, but access is granted per machine.
    $NET_ISO  air gap: no IP, no DHCP, no host address on that
                    segment. Static IP, e.g. 10.66.66.0/24

  All three block your LAN, tailnet, zerotier, IPv6, mail and SMB.

  ONLY FOR $NET_NAT VMs
    vmnet list                who has access right now
    vmnet on  <vm>            grant it (at runtime, no VM restart)
    vmnet off <vm>            revoke it

  IF SOMETHING STOPS BOOTING
    $0 complain     drops the AppArmor block instantly
    $0 verify       checks everything is still active

  For anything dangerous: network '$NET_ISO' and a snapshot first.
========================================================================

EOF
  [[ "${RELOGIN:-0}" == "1" ]] && warn "LOG OUT AND BACK IN (libvirt group)"
  echo
}

# --- STATUS -----------------------------------------------------------------
cmd_status() {
  if ! state_load; then
    echo "The lab is not installed (no $STATE_FILE)."
    return 0
  fi
  echo "=== qemu-secure-lab ${SCRIPT_VERSION} (state v${LAB_VERSION:-?}) ==="
  echo "user:            ${LAB_USER:-?}"
  echo "outbound iface:  ${IFACE_NET:-?}"
  echo "NAT bridge:      ${BR_NAT:-?}  (gw ${BRIDGE_IP:-?})"
  echo "isolated bridge: ${BR_ISO:-?}"
  echo "VM root:         ${VMS_ROOT:-?}"
  echo "packages:        ${PKGS_NEW:-none new}"
  echo "services:        ${SVC_NEW:-none new}"
  echo "networks made:   ${NETS_NEW:-none}"
  echo "pools made:      ${POOLS_NEW:-none}"
  echo "QEMU user:       ${QEMU_USER:-root (not hardened)}"
  echo "QEMU derooted:   ${QEMU_USER_HARDENED:-0}"
  echo
  echo "--- QEMU AppArmor profile ---"
  if sudo test -f "$QEMU_PROFILE_PATH" 2>/dev/null; then
    profile_in_complain \
      && echo "  installed, COMPLAIN mode (not blocking)" \
      || echo "  installed, ENFORCING"
  else
    echo "  not installed"
  fi
  echo "--- AppArmor kernel ---"
  apparmor_active && echo "  ACTIVE" || echo "  inactive (reboot pending)"
  echo "--- vmguard ---"
  sudo nft list table inet vmguard >/dev/null 2>&1 && echo "  loaded" || echo "  NOT loaded"
  echo
  echo "--- internet per VM ---"
  command -v vmnet >/dev/null && sudo vmnet list || echo "  helper missing"
}

# --- VERIFY -----------------------------------------------------------------
cmd_verify() {
  need_user
  state_load || true
  local failures=0
  info "Checking what is ACTUALLY active"

  sudo nft list table inet vmguard >/dev/null 2>&1 \
    && ok "vmguard loaded in the kernel" \
    || { bad "vmguard NOT loaded"; failures=$((failures+1)); }

  sudo ufw status 2>/dev/null | head -1 | grep -q active \
    && ok "UFW active" \
    || { bad "UFW not active"; failures=$((failures+1)); }

  apparmor_active \
    && ok "AppArmor activo en el kernel" \
    || { bad "AppArmor NOT active (reboot pending)"; failures=$((failures+1)); }

  sudo grep -qE '^user[[:space:]]*=' /etc/libvirt/qemu.conf 2>/dev/null \
    && ok "QEMU does not run as root" \
    || { bad "QEMU would run as root"; failures=$((failures+1)); }

  sudo virsh net-info "$NET_ISO" &>/dev/null \
    && ok "network '$NET_ISO' defined" \
    || { bad "network '$NET_ISO' is missing"; failures=$((failures+1)); }

  if sudo test -f "$QEMU_PROFILE_PATH"; then
    profile_in_complain \
      && warn "QEMU profile in complain mode (not blocking yet)" \
      || ok "QEMU profile enforcing"
  else
    warn "QEMU profile not installed"
  fi

  # The MAC set must exist even with no elements in it
  sudo nft list set inet vmguard vm_inet >/dev/null 2>&1 \
    && ok "per-VM internet control operational" \
    || { bad "the vm_inet set does not exist"; failures=$((failures+1)); }

  echo
  ((failures)) && warn "$failures check(s) failed" || ok "everything critical is active"
  cat <<EOF

  Manual check, with a VM running:
    ps -eo user,cmd | grep qemu-system     -> should say libvirt-qemu
    sudo aa-status | grep -A2 qemu-lab     -> should list the PID

  FROM INSIDE a lab-nat VM with no internet grant:
    ip -4 addr              -> should hold ${NAT_SUBNET:-192.168.150}.x (DHCP ok)
    getent hosts debian.org -> should NOT resolve without a grant
                               (DNS follows the same allowlist as outbound
                               traffic, to close DNS-based exfiltration)

    ping 1.1.1.1        -> FAILS
    ping 192.168.1.1    -> FAILS (your router)
    ping 100.64.0.1     -> FAILS (tailnet)
    ping ${BRIDGE_IP:-192.168.150.1}    -> ALSO FAILS, and that is correct:
        only DHCP and DNS reach the host, ICMP is cut.
        A gateway not answering ping does NOT mean there is no network;
        check it with the two commands above.

  After 'vmnet on <vm>', only 1.1.1.1 should start replying.
  The other two must keep failing. If they answer, something is wrong.

EOF
}

# --- configuration rollback -------------------------------------------------
revert_config() {
  if command -v ufw >/dev/null; then
    info "Removing UFW rules"
    sudo ufw route delete allow in on "${BR_NAT:-virbr-lab}" out on "${IFACE_NET:-eth0}" >/dev/null 2>&1 || true
    sudo ufw route delete allow in on "${BR_FREE:-virbr-open}" out on "${IFACE_NET:-eth0}" >/dev/null 2>&1 || true
    sudo ufw delete allow in on "${BR_FREE:-virbr-open}" to any port 67 proto udp >/dev/null 2>&1 || true
    sudo ufw delete allow in on "${BR_FREE:-virbr-open}" to "${FREE_IP:-192.168.171.1}" port 53 proto udp >/dev/null 2>&1 || true
    sudo ufw delete allow in on "${BR_FREE:-virbr-open}" to "${FREE_IP:-192.168.171.1}" port 53 proto tcp >/dev/null 2>&1 || true
    sudo ufw delete allow in on "${BR_NAT:-virbr-lab}" to any port 67 proto udp >/dev/null 2>&1 || true
    sudo ufw delete allow in on "${BR_NAT:-virbr-lab}" to "${BRIDGE_IP:-192.168.150.1}" port 53 proto udp >/dev/null 2>&1 || true
    sudo ufw delete allow in on "${BR_NAT:-virbr-lab}" to "${BRIDGE_IP:-192.168.150.1}" port 53 proto tcp >/dev/null 2>&1 || true
    restore_file /etc/default/ufw
    sudo ufw reload >/dev/null 2>&1 || true
    if [[ "${UFW_WAS_ACTIVE:-1}" == "0" ]]; then
      sudo ufw disable >/dev/null 2>&1 || true
      warn "UFW disabled (it was off before). The machine has no firewall now."
    fi
    ok "UFW reverted"
  fi

  info "Removing vmguard and the internet control"
  sudo systemctl disable --now vmguard.service >/dev/null 2>&1 || true
  sudo rm -f /etc/systemd/system/vmguard.service "$NFT_FILE" "$LOADER" "$HELPER"
  sudo rmdir /etc/nftables.d 2>/dev/null || true
  sudo systemctl daemon-reload
  sudo nft delete table inet vmguard >/dev/null 2>&1 || true
  ok "vmguard and vmnet removed"

  local n
  if [[ -n "${POOLS_NEW:-}" ]]; then
    info "Removing pools created by the script (files are NOT deleted)"
    for n in ${POOLS_NEW}; do
      sudo virsh pool-destroy  "$n" >/dev/null 2>&1 || true
      sudo virsh pool-undefine "$n" >/dev/null 2>&1 || true
      ok "pool '$n' removed"
    done
  fi
  if [[ -n "${NETS_NEW:-}" ]]; then
    info "Removing networks created by the script"
    for n in ${NETS_NEW}; do
      sudo virsh net-destroy  "$n" >/dev/null 2>&1 || true
      sudo virsh net-undefine "$n" >/dev/null 2>&1 || true
      ok "network '$n' removed"
    done
  fi

  if sudo test -f "$QEMU_PROFILE_PATH" 2>/dev/null; then
    info "Removing the QEMU AppArmor profile"
    sudo apparmor_parser -R "$QEMU_PROFILE_PATH" >/dev/null 2>&1 || true
    sudo rm -f "$QEMU_PROFILE_PATH"
    ok "profile removed"
  fi

  if [[ "${ACL_APPLIED:-0}" == "1" ]] && command -v setfacl >/dev/null; then
    info "Removing ACLs for '${QEMU_USER:-libvirt-qemu}'"
    local qu="${QEMU_USER:-libvirt-qemu}" vm_root="${VMS_ROOT:-$HOME/VMs}"
    sudo setfacl    -x "u:${qu}" "$HOME"                        2>/dev/null || true
    sudo setfacl    -x "u:${qu}" "$vm_root"                       2>/dev/null || true
    sudo setfacl -R -x "u:${qu}" "$vm_root/ISOs" "$vm_root/QEMU"    2>/dev/null || true
    sudo setfacl -R -d -x "u:${qu}" "$vm_root/ISOs" "$vm_root/QEMU" 2>/dev/null || true
    ok "ACLs removed"
  fi
  if [[ "${QCONF_MODIFIED:-0}" == "1" ]]; then
    info "Reverting qemu.conf"
    restore_file /etc/libvirt/qemu.conf
    sudo systemctl restart libvirtd.service >/dev/null 2>&1 || true
  fi

  if [[ "${GRUB_MODIFIED:-0}" == "1" ]]; then
    info "Restoring the GRUB kernel command line"
    if [[ -n "${GRUB_CMDLINE_ORIG:-}" ]]; then
      awk -v old="$GRUB_CMDLINE_ORIG" '
        /^GRUB_CMDLINE_LINUX_DEFAULT=/ && !d { print old; d=1; next } { print }
      ' /etc/default/grub | sudo tee /etc/default/grub.lab >/dev/null
      sudo mv /etc/default/grub.lab /etc/default/grub
    else
      restore_file /etc/default/grub
    fi
    sudo grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1 || warn "grub-mkconfig failed"
    ok "GRUB restored (effective after reboot)"
  fi
  if [[ "${SDBOOT_MODIFIED:-0}" == "1" ]] && sudo test -f "$BACKUP_DIR/loader-entries.tar"; then
    sudo tar -xf "$BACKUP_DIR/loader-entries.tar" -C /boot/loader
    ok "systemd-boot entries restored"
  fi
  if [[ "${UKI_MODIFIED:-0}" == "1" ]]; then
    restore_file /etc/kernel/cmdline
    sudo mkinitcpio -P >/dev/null 2>&1 || warn "mkinitcpio fallo"
  fi
  if [[ "${AA_SVC_ENABLED_BY_US:-0}" == "1" ]]; then
    sudo systemctl disable --now apparmor.service >/dev/null 2>&1 || true
    ok "apparmor.service disabled"
  fi

  if [[ "${GROUP_ADDED:-0}" == "1" ]]; then
    sudo gpasswd -d "${LAB_USER:-$USER}" libvirt >/dev/null 2>&1 || true
    ok "user removed from the libvirt group"
  fi
}

# --- UNINSTALL --------------------------------------------------------------
cmd_uninstall() {
  need_user
  local yes=0 soft=0 a
  for a in "$@"; do
    [[ "$a" == "-y" || "$a" == "--yes"  ]] && yes=1
    [[ "$a" == "--soft" ]] && soft=1
  done

  state_load || warn "no prior state; cleaning up the known pieces blindly"

  local vm_list vm_root
  vm_list="$(list_vms)"
  vm_root="${VMS_ROOT:-$HOME/VMs}"

  echo
  if ((soft)); then
    echo "  UNINSTALL --soft: reverts configuration, keeps qemu installed."
  else
    echo "  UNINSTALL: leaves the machine as if this had never been installed."
    echo "  Configuration is reverted AND these are removed:"
    echo "      ${PKGS_PURGE[*]}"
    echo "  (never touched: ${PKGS_PROTECTED[*]} and apparmor)"
  fi
  echo
  echo "  NONE OF YOUR FILES ARE DELETED:"
  echo "    - disks and ISOs in $vm_root"
  echo "    - VM definitions in /etc/libvirt/qemu/"
  if [[ -n "$vm_list" ]]; then
    echo
    warn "you have VMs defined:"
    echo "$vm_list" | sed 's/^/        - /'
    ((soft)) || warn "after uninstall they will not boot until you reinstall qemu"
  fi
  echo
  if ! ((yes)); then
    local answer
    read -r -p "  Type YES to continue: " answer || answer=""
    [[ "$answer" == "YES" ]] || { echo "Cancelled."; return 0; }
  fi

  revert_config

  if ! ((soft)); then
    info "Stopping libvirt services"
    local s
    for s in libvirtd.service libvirtd.socket virtlogd.service virtlogd.socket; do
      sudo systemctl disable --now "$s" >/dev/null 2>&1 || true
    done
    ok "services stopped"

    local to_remove=() p prot skip
    for p in "${PKGS_PURGE[@]}"; do
      pacman -Qq "$p" &>/dev/null || continue
      skip=0
      for prot in "${PKGS_PROTECTED[@]}"; do [[ "$p" == "$prot" ]] && skip=1; done
      ((skip)) || to_remove+=("$p")
    done
    if ((${#to_remove[@]})); then
      info "Removing: ${to_remove[*]}"
      sudo pacman -Rns --noconfirm "${to_remove[@]}" \
        || warn "pacman could not remove everything (dependencies). Check by hand."
    else
      ok "no lab packages were installed"
    fi
  fi

  sudo rm -rf "$STATE_DIR"
  ok "state removed"

  cat <<EOF

========================================================================
  UNINSTALLED

  STILL THERE (they are yours, delete them yourself if you want):
    $vm_root                    .qcow2 disks and ISOs
    /etc/libvirt/qemu/*.xml   VM definitions

  If the kernel command line was touched, REBOOT to finish the rollback.
========================================================================

EOF
}

# --- main -------------------------------------------------------------------
case "${1:-}" in
  ""|install|--install)  cmd_auto ;;
  status)                cmd_status ;;
  verify)                cmd_verify ;;
  enforce)               need_user; switch_to_enforce ;;
  complain)              need_user; switch_to_complain ;;
  uninstall|purge)       shift; cmd_uninstall "$@" ;;
  -h|--help|help)
    cat <<EOF
qemu-secure-lab-1.0.1-EN.sh $SCRIPT_VERSION
Hardened QEMU/KVM lab for Arch Linux.

  $0 [command]

  (no command)      install and advance; safe to repeat
  status            recorded configuration
  verify            check what is really active
  enforce           put AppArmor into enforce mode now
  complain          back to complain mode (if something stops booting)
  uninstall         leave the machine as before (also removes qemu)
  uninstall --soft  revert configuration, keep qemu installed

Per-VM internet access, once installed:
  vmnet list | vmnet on <vm> | vmnet off <vm> | vmnet off-all

Never deletes your VMs, disks or ISOs.
Variables: IFACE_NET, VMS_ROOT
EOF
    ;;
  *) die "Unknown command: $1   (try: $0 --help)" ;;
esac
