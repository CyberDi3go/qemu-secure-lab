#!/usr/bin/env bash
#
# qemu-secure-lab - laboratorio QEMU/KVM aislado para Arch Linux
#
# Monta un entorno de virtualizacion para practicas de seguridad: QEMU sin
# privilegios, perfil AppArmor propio, red segmentada y salida a internet
# concedida por maquina en lugar de global.
#
# Requiere Arch Linux, virtualizacion por hardware, systemd y sudo.
#
#
# INSTALACION
#
#   ./qemu-secure-lab-1.0.1-ES.sh
#
# Se ejecuta varias veces y cada pasada avanza desde donde quedo la anterior.
# La primera deja lista la red, el almacenamiento y el deprivilegio de QEMU, y
# pide reiniciar: AppArmor se habilita en la linea de kernel y no admite carga
# en caliente. La segunda carga el perfil de QEMU en modo registro. La tercera
# revisa ese registro y pasa a bloqueo si no quedan denegaciones pendientes.
# Repetir la orden no rehace lo que ya esta hecho.
#
#
# SALIDA A INTERNET
#
# Se decide por la red que tenga asignada la VM, desde el desplegable de
# virt-manager. No hace falta ninguna orden.
#
#   lab-libre     sale a internet sin mas tramite
#   lab-nat       aislada; la salida se concede por maquina
#   lab-aislada   sin salida de ningun tipo
#
# Para las VMs de lab-nat, el permiso se gestiona con vmnet, se aplica sobre
# la MAC en caliente y persiste entre arranques del host:
#
#   vmnet list          estado de cada VM
#   vmnet on  <vm>      concede salida
#   vmnet off <vm>      la retira
#   vmnet off-all       corta a todas
#
# Retirar el permiso quita tambien la resolucion DNS.
#
#
# OTRAS ORDENES
#
#   ./qemu-secure-lab-1.0.1-ES.sh <orden>
#
#   status            configuracion registrada
#   verify            comprueba lo que esta activo en el kernel
#   enforce           fuerza el bloqueo de AppArmor
#   complain          devuelve el perfil a modo registro
#   uninstall         revierte todo y desinstala los paquetes
#   uninstall --soft  revierte solo la configuracion
#
# uninstall no toca discos, ISOs ni definiciones de VM.
#
#
# REDES
#
#   lab-libre     NAT con DHCP y DNS, salida directa a internet. Filtrada
#                 igual que lab-nat en todo lo demas.
#   lab-nat       NAT con DHCP y DNS, pero la salida y la resolucion de
#                 nombres solo llegan a las MAC autorizadas.
#   lab-aislada   sin IP, sin DHCP y sin direccion del host en el segmento.
#                 Las VMs se ven entre si y nada mas.
#
# Las tres bloquean la LAN del host, tailnet, zerotier, link-local, IPv6, el
# correo saliente y SMB/RPC/RDP. Las VMs de una misma red se ven entre si;
# cruzar de una red a otra no es posible.
#
#
# LIMITACIONES CONOCIDAS
#
#   - El perfil de AppArmor es unico para todas las VMs. Arch compila libvirt
#     sin virt-aa-helper, de modo que no hay confinamiento por maquina: el
#     perfil aisla del host, no unas VMs de otras.
#   - Las VMs de una misma red se ven entre si. Es deliberado, hace falta para
#     las practicas de varias maquinas.
#   - Una VM puede suplantar la MAC de otra autorizada y heredar su salida.
#     Se cierra anadiendo <filterref filter='clean-traffic'/> a la interfaz.
#   - Las redes en modo bridge o macvtap no pasan por estas reglas.
#   - Compartir portapapeles, carpetas o USB con una VM anula buena parte del
#     aislamiento. Son ajustes por maquina y el script no los toca.
#
# Variables de entorno: IFACE_NET (interfaz de salida), VMS_ROOT (raiz de
# discos e ISOs). Ejecutar como usuario normal; pide sudo cuando lo necesita.

set -euo pipefail

# --- constantes -------------------------------------------------------------
SCRIPT_VERSION="1.0.1"
# Version del formato de /var/lib/qemu-lab/state.env, no del script.
# Solo sube si un cambio deja de ser compatible con un estado ya escrito.
LAB_VERSION="5"
STATE_DIR="/var/lib/qemu-lab"
STATE_FILE="$STATE_DIR/state.env"
BACKUP_DIR="$STATE_DIR/backups"
ALLOW_FILE="$STATE_DIR/inet-allow"

VMS_ROOT="${VMS_ROOT:-$HOME/VMs}"
ISO_DIR="$VMS_ROOT/ISOs"
DISK_DIR="$VMS_ROOT/QEMU"
POOL_ISOS="lab-ISOs"
POOL_DISCOS="lab-discos"

NET_NAT="lab-nat"
NET_ISO="lab-aislada"
NET_FREE="lab-libre"
BR_NAT="virbr-lab"
BR_ISO="virbr-iso"
BR_FREE="virbr-free"
# Se resuelve en tiempo de ejecucion: ver elegir_subred
NAT_SUBNET=""
BRIDGE_IP=""
FREE_SUBNET=""
FREE_IP=""
SUBREDES_CANDIDATAS=(192.168.150 192.168.171 192.168.213 10.150.42 172.28.150)

PKGS_BASE=(qemu-desktop libvirt virt-manager dnsmasq iptables-nft nftables
           edk2-ovmf swtpm ufw acl apparmor)

# Intocables: quitarlos dejaria el sistema sin cortafuegos o sin ACLs
PKGS_PROTEGIDOS=(acl iptables-nft nftables ufw)
# El laboratorio en si, lo unico que retira 'uninstall'
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

# --- estado -----------------------------------------------------------------
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

# No sobrescribe: registra el estado previo para poder revertirlo despues.
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
    ok "restaurado $f"
  fi
}

# --- utilidades -------------------------------------------------------------
need_user() {
  [[ $EUID -eq 0 ]] && die "No lo lances con sudo. Ejecutalo como tu usuario."
  command -v pacman >/dev/null || die "Esto es solo para Arch Linux."
  sudo -v || die "Se necesita sudo."
  ensure_dirs
}

# Un estado escrito por una version incompatible describe otras redes y otras
# reglas. Mezclarlas deja configuracion huerfana, asi que se aborta.
comprobar_estado_previo() {
  sudo test -f "$STATE_FILE" || return 0
  local v
  v="$(sudo grep -E '^LAB_VERSION=' "$STATE_FILE" 2>/dev/null | cut -d= -f2 | tr -d "'\"" || true)"
  [[ -z "$v" || "$v" == "5" ]] && return 0
  echo
  bad "Hay una instalacion previa con formato de estado v${v}."
  echo
  echo "  Esta version usa otras redes y otras reglas de cortafuegos, y"
  echo "  mezclarlas dejaria configuracion huerfana."
  echo
  echo "  Desinstala la anterior con el script que la creo (no borra VMs ni"
  echo "  discos) y vuelve a lanzar este:"
  echo "      ./<script-anterior>.sh uninstall"
  echo
  die "Cancelado sin tocar nada."
}

# firewalld y UFW gestionan las mismas tablas; con las dos activas las reglas
# se pisan de forma impredecible.
comprobar_firewall() {
  if systemctl is-active --quiet firewalld 2>/dev/null; then
    echo
    bad "firewalld esta activo en este equipo."
    echo "  Este script configura UFW, y las dos herramientas compiten por las"
    echo "  mismas tablas de netfilter. Desactiva una de las dos antes de seguir:"
    echo "      sudo systemctl disable --now firewalld"
    echo
    die "Cancelado sin tocar nada."
  fi
}

comprobar_kvm() {
  if ! grep -qE '^flags[[:space:]]*:.*[[:space:]](vmx|svm)([[:space:]]|$)' /proc/cpuinfo; then
    warn "la CPU no expone vmx ni svm: la virtualizacion por hardware esta"
    warn "desactivada en la BIOS/UEFI o no existe. Las VMs irian emuladas."
  fi
}

detect_iface() {
  if [[ -z "${IFACE_NET:-}" ]]; then
    IFACE_NET="$(ip route show default 2>/dev/null \
      | grep -vE 'tailscale|virbr|zt|docker' | awk '/default/{print $5; exit}' || true)"
  fi
  [[ -n "${IFACE_NET:-}" ]] || die "No detecto la interfaz de internet. Usa: IFACE_NET=xxx $0"
}

apparmor_activo() {
  [[ -d /sys/kernel/security/apparmor ]] && \
  grep -qw apparmor /sys/kernel/security/lsm 2>/dev/null
}

# /boot suele ser la ESP montada con umask 0077, de modo que sin sudo la
# deteccion cae siempre en "desconocido".
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

listar_vms() {
  command -v virsh >/dev/null || return 0
  sudo virsh list --all --name 2>/dev/null | grep -v '^$' || true
}

# --- paquetes y servicios ---------------------------------------------------
paso_paquetes() {
  info "Paquetes"
  local nuevos=() p
  # qemu-full ya incluye qemu-desktop; pedir el segundo con el primero puesto
  # confunde a pacman en algunas instalaciones.
  if pacman -Qq qemu-full &>/dev/null; then
    PKGS_BASE=("${PKGS_BASE[@]/qemu-desktop/qemu-full}")
    PKGS_PURGE=("${PKGS_PURGE[@]/qemu-desktop/qemu-full}")
  fi
  for p in "${PKGS_BASE[@]}"; do
    pacman -Qq "$p" &>/dev/null || nuevos+=("$p")
  done
  sudo pacman -S --needed --noconfirm "${PKGS_BASE[@]}"
  state_set_once PKGS_NEW "${nuevos[*]:-}"
  if ((${#nuevos[@]})); then ok "instalados: ${nuevos[*]}"; else ok "ya estaban todos"; fi
}

paso_servicios() {
  info "Servicios de libvirt"
  local svc_new=() s
  for s in libvirtd.service virtlogd.socket; do
    if systemctl is-enabled --quiet "$s" 2>/dev/null; then
      ok "$s ya estaba habilitado"
    else
      sudo systemctl enable "$s" >/dev/null 2>&1 || true
      svc_new+=("$s")
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
  state_set_once SVC_NEW "${svc_new[*]:-}"
  ok "libvirtd, virtlogd y apparmor.service habilitados"
}

paso_grupo() {
  info "Grupo libvirt"
  if id -nG "$USER" | grep -qw libvirt; then
    ok "ya estabas en el grupo"
    state_set_once GROUP_ADDED 0
    RELOGIN=0
  else
    sudo usermod -aG libvirt "$USER"
    state_set_once GROUP_ADDED 1
    warn "te he anadido al grupo: hay que cerrar sesion y volver a entrar"
    RELOGIN=1
  fi
}

# Una subred fija choca si el equipo ya la usa en su LAN o en otra VPN. Si la
# red del laboratorio ya existe se respeta la suya; si no, se toma la primera
# candidata que no aparezca en las rutas ni en las direcciones locales.
subred_en_uso() {
  local c="$1"
  ip -4 route show 2>/dev/null | grep -qE "(^| )${c//./\\.}\\." && return 0
  ip -4 addr  show 2>/dev/null | grep -qE "inet ${c//./\\.}\\."  && return 0
  return 1
}

# Prefijo /24 de una red de libvirt ya definida, vacio si no existe.
subred_de_red() {
  local red="$1" actual
  sudo virsh net-info "$red" &>/dev/null || return 0
  actual="$(sudo virsh net-dumpxml "$red" 2>/dev/null \
    | sed -n "s:.*<ip address='\\([0-9.]*\\)'.*:\\1:p" | head -1 || true)"
  [[ "$actual" =~ ^([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+$ ]] || return 0
  printf '%s' "${BASH_REMATCH[1]}"
}

elegir_subred() {
  local c
  NAT_SUBNET="$(subred_de_red "$NET_NAT")"
  FREE_SUBNET="$(subred_de_red "$NET_FREE")"

  for c in "${SUBREDES_CANDIDATAS[@]}"; do
    [[ -n "$NAT_SUBNET" && -n "$FREE_SUBNET" ]] && break
    [[ "$c" == "$NAT_SUBNET" || "$c" == "$FREE_SUBNET" ]] && continue
    subred_en_uso "$c" && continue
    if [[ -z "$NAT_SUBNET" ]]; then NAT_SUBNET="$c"; else FREE_SUBNET="$c"; fi
  done

  if [[ -z "$NAT_SUBNET" || -z "$FREE_SUBNET" ]]; then
    warn "quedan pocas subredes libres; reviso las candidatas por defecto"
    [[ -n "$NAT_SUBNET"  ]] || NAT_SUBNET="${SUBREDES_CANDIDATAS[0]}"
    [[ -n "$FREE_SUBNET" ]] || FREE_SUBNET="${SUBREDES_CANDIDATAS[1]}"
  fi
  BRIDGE_IP="${NAT_SUBNET}.1"
  FREE_IP="${FREE_SUBNET}.1"
}

# --- redes ------------------------------------------------------------------
paso_redes() {
  info "Redes del laboratorio"
  elegir_subred
  ok "lab-nat   ${NAT_SUBNET}.0/24 (gw $BRIDGE_IP)"
  ok "lab-libre ${FREE_SUBNET}.0/24 (gw $FREE_IP)"
  local nets_new=() tmpxml

  # Red propia. La 'default' de libvirt se deja intacta; aun asi queda
  # cubierta por vmguard, que filtra cualquier interfaz virbr*.
  if sudo virsh net-info "$NET_NAT" &>/dev/null; then
    ok "red '$NET_NAT' ya existia"
  else
    tmpxml="$(mktemp)"
    cat > "$tmpxml" <<EOF
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
    sudo virsh net-define "$tmpxml" >/dev/null \
      || die "No pude definir la red $NET_NAT"
    nets_new+=("$NET_NAT")
    rm -f "$tmpxml"
    ok "red '$NET_NAT' creada ($BR_NAT, gw $BRIDGE_IP)"
  fi
  sudo virsh net-autostart "$NET_NAT" >/dev/null 2>&1 || true
  sudo virsh net-start     "$NET_NAT" >/dev/null 2>&1 || true

  # Igual que lab-nat pero exenta de la lista blanca: para VMs de confianza
  # que necesitan internet sin tener que autorizarlas una a una. Conserva el
  # resto del filtrado (nada de LAN, VPN, IPv6, correo ni SMB).
  if sudo virsh net-info "$NET_FREE" &>/dev/null; then
    ok "red '$NET_FREE' ya existia"
  else
    tmpxml="$(mktemp)"
    cat > "$tmpxml" <<EOF
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
    sudo virsh net-define "$tmpxml" >/dev/null \
      || die "No pude definir la red $NET_FREE"
    nets_new+=("$NET_FREE")
    rm -f "$tmpxml"
    ok "red '$NET_FREE' creada ($BR_FREE, gw $FREE_IP)"
  fi
  sudo virsh net-autostart "$NET_FREE" >/dev/null 2>&1 || true
  sudo virsh net-start     "$NET_FREE" >/dev/null 2>&1 || true

  # Air gap: sin <forward> y sin <ip>. Ni NAT, ni dnsmasq, ni direccion del
  # host en el segmento. Las VMs necesitan IP estatica.
  if sudo virsh net-info "$NET_ISO" &>/dev/null; then
    ok "red '$NET_ISO' ya existia"
  else
    tmpxml="$(mktemp)"
    cat > "$tmpxml" <<EOF
<network>
  <name>$NET_ISO</name>
  <bridge name='$BR_ISO' stp='on' delay='0'/>
</network>
EOF
    if sudo virsh net-define "$tmpxml" >/dev/null 2>&1; then
      nets_new+=("$NET_ISO")
      ok "red '$NET_ISO' creada ($BR_ISO, sin IP, sin DHCP, air gap)"
    else
      warn "no pude definir '$NET_ISO'; creala a mano en virt-manager"
    fi
    rm -f "$tmpxml"
  fi
  sudo virsh net-autostart "$NET_ISO" >/dev/null 2>&1 || true
  sudo virsh net-start     "$NET_ISO" >/dev/null 2>&1 || true

  state_set_once NETS_NEW "${nets_new[*]:-}"
  state_set BR_NAT    "$BR_NAT"
  state_set BR_ISO    "$BR_ISO"
  state_set BR_FREE   "$BR_FREE"
  state_set BRIDGE_IP "$BRIDGE_IP"
  state_set FREE_IP   "$FREE_IP"
}

# --- firewall ---------------------------------------------------------------
paso_ufw() {
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

  # El DHCP viaja a broadcast, no admite acotarse por IP de destino.
  sudo ufw allow in on "$BR_NAT" to any port 67 proto udp \
       comment 'qemu-lab DHCP' >/dev/null
  sudo ufw allow in on "$BR_NAT" to "$BRIDGE_IP" port 53 proto udp \
       comment 'qemu-lab DNS' >/dev/null
  sudo ufw allow in on "$BR_NAT" to "$BRIDGE_IP" port 53 proto tcp \
       comment 'qemu-lab DNS' >/dev/null

  # UFW abre el reenvio y vmguard decide, ya que corre a prioridad -10 y se
  # evalua antes. Sin esta regla no saldria ninguna VM ni estando autorizada.
  sudo ufw route allow in on "$BR_NAT" out on "$IFACE_NET" >/dev/null 2>&1 || true

  sudo ufw allow in on "$BR_FREE" to any port 67 proto udp \
       comment 'qemu-lab DHCP libre' >/dev/null
  sudo ufw allow in on "$BR_FREE" to "$FREE_IP" port 53 proto udp \
       comment 'qemu-lab DNS libre' >/dev/null
  sudo ufw allow in on "$BR_FREE" to "$FREE_IP" port 53 proto tcp \
       comment 'qemu-lab DNS libre' >/dev/null
  sudo ufw route allow in on "$BR_FREE" out on "$IFACE_NET" >/dev/null 2>&1 || true

  state_set UFW_RULES 1
  ok "deny incoming / deny routed, DHCP y DNS acotados al bridge"
}

# --- vmguard ----------------------------------------------------------------
paso_vmguard() {
  info "vmguard (contencion de red de las VMs)"
  sudo mkdir -p /etc/nftables.d
  sudo tee "$NFT_FILE" > /dev/null <<EOF
# vmguard - contencion de red de las VMs del laboratorio
# Generado por qemu-secure-lab-1.0.1-ES.sh
# Se retira con: ./qemu-secure-lab-1.0.1-ES.sh uninstall
#
# Prioridad -10: se evalua antes que UFW (0) y que las tablas de libvirt. Un
# drop aqui es definitivo; un accept no exime de las reglas posteriores.
#
# El conjunto vm_inet guarda las MAC con permiso de salida, y lo gestiona
# vmnet on/off.

table inet vmguard
delete table inet vmguard
table inet vmguard {

    # MAC con permiso de salida. Vacio significa que no sale ninguna VM.
    set vm_inet {
        type ether_addr
    }

    # Rangos que no son internet publico: LAN, tailnet, zerotier, link-local
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
        # El bridge aislado no habla con el host
        iifname "$BR_ISO" counter drop

        # DHCP: destino broadcast, no admite acotarse por IP
        udp dport 67 accept

        # La red libre resuelve sin restriccion: ya tiene salida concedida
        iifname "$BR_FREE" udp dport 53 fib daddr type local accept
        iifname "$BR_FREE" tcp dport 53 fib daddr type local accept

        # En lab-nat el DNS va por la misma lista blanca que la salida. Sin
        # esta restriccion, una VM sin permiso aun puede exfiltrar datos en
        # subdominios, porque dnsmasq reenvia la consulta hacia fuera.
        ether saddr @vm_inet udp dport 53 fib daddr type local accept
        ether saddr @vm_inet tcp dport 53 fib daddr type local accept

        # Cualquier otro servicio del host queda fuera de alcance
        counter drop
    }

    chain input {
        type filter hook input priority -10; policy accept;
        iifname "virbr*" jump vm_host
    }

    # ------------------------------------------------------- VM -> RESTO DEL MUNDO
    chain vm_salida {
        # Air gap: trafico solo entre VMs del mismo bridge aislado
        iifname "$BR_ISO" oifname "$BR_ISO" accept
        iifname "$BR_ISO" counter drop

        # Practicas de varias maquinas dentro de un mismo bridge
        iifname "$BR_NAT" oifname "$BR_NAT" accept
        iifname "$BR_FREE" oifname "$BR_FREE" accept

        # Nunca se salta de un bridge de VMs a otro
        oifname "virbr*" counter drop

        # Fuera las redes privadas del host
        ip daddr @privadas_v4 counter drop

        # IPv6 cortado: las redes del laboratorio no lo usan
        meta nfproto ipv6 counter drop

        # Correo saliente
        tcp dport { 25, 465, 587, 2525 } counter drop

        # Propagacion lateral: SMB, NetBIOS, RPC, RDP
        tcp dport { 135, 137, 138, 139, 445, 3389 } counter drop
        udp dport { 137, 138, 139, 445 } counter drop

        # Evita que la IP publica del host acabe fichada por escaneo
        ct state new limit rate over 100/second burst 200 packets counter drop

        # La red libre sale sin necesidad de autorizacion por MAC
        iifname "$BR_FREE" accept

        # En el resto, la salida depende de la lista blanca
        ether saddr @vm_inet accept
        counter drop
    }

    # ------------------------------------------------------- MUNDO -> VM
    chain vm_entrada {
        # Respuestas a lo que la VM inicio
        ct state established,related accept
        # Nadie de fuera abre conexiones hacia una VM
        counter drop
    }

    chain forward {
        type filter hook forward priority -10; policy accept;
        iifname "virbr*" jump vm_salida
        oifname "virbr*" jump vm_entrada
    }
}
EOF

  # Cargador: aplica el ruleset y repuebla las MAC autorizadas, de forma que
  # los permisos sobrevivan a un reinicio del host.
  sudo tee "$LOADER" > /dev/null <<EOF
#!/usr/bin/env bash
# Carga vmguard y restaura los permisos de salida por VM.
# Generado por qemu-secure-lab-1.0.1-ES.sh
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
Description=Contencion de red para las VMs del laboratorio (vmguard)
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
    || die "vmguard no cargo. Mira el error con: sudo nft -f $NFT_FILE"
  state_set VMGUARD 1
  ok "vmguard activo (por defecto ninguna VM sale a internet)"
}

# --- helper vmnet -----------------------------------------------------------
paso_helper() {
  info "Instalando el mando de internet por VM ($HELPER)"
  sudo tee "$HELPER" > /dev/null <<EOF
#!/usr/bin/env bash
# vmnet - concede o retira salida a internet a una VM, en caliente.
# Generado por qemu-secure-lab-1.0.1-ES.sh
#
#   vmnet on  <vm>     concede salida
#   vmnet off <vm>     la retira
#   vmnet list         estado de todas las VMs
#   vmnet off-all      corta a todas
#
# El permiso queda registrado en $ALLOW_FILE y sobrevive a los reinicios.
set -euo pipefail

ALLOW="$ALLOW_FILE"
NET_ISO="$NET_ISO"
NET_FREE="$NET_FREE"

macs_de() {
  sudo virsh domiflist "\$1" 2>/dev/null \\
    | awk 'tolower(\$NF) ~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}\$/ {print tolower(\$NF)}'
}

redes_de() {
  sudo virsh domiflist "\$1" 2>/dev/null | awk 'tolower(\$NF) ~ /^([0-9a-f]{2}:){5}[0-9a-f]{2}\$/ {print \$3}'
}

existe_vm() {
  sudo virsh dominfo "\$1" &>/dev/null
}

en_set() {
  sudo nft list set inet vmguard vm_inet 2>/dev/null | grep -qi "\$1"
}

case "\${1:-}" in
  on)
    vm="\${2:-}"; [[ -n "\$vm" ]] || { echo "uso: vmnet on <vm>"; exit 1; }
    existe_vm "\$vm" || { echo "No existe la VM '\$vm'. Mira: sudo virsh list --all"; exit 1; }
    macs="\$(macs_de "\$vm" || true)"
    [[ -n "\$macs" ]] || { echo "'\$vm' no tiene ninguna tarjeta de red."; exit 1; }
    if redes_de "\$vm" | grep -qx "\$NET_ISO"; then
      echo "[!] '\$vm' esta en la red '\$NET_ISO' (air gap)."
      echo "    Esa red no tiene salida por diseno: el permiso no hara nada."
      echo "    Cambiale la tarjeta de red en virt-manager."
    fi
    if redes_de "\$vm" | grep -qx "\$NET_FREE"; then
      echo "[!] '\$vm' ya esta en la red '\$NET_FREE', que sale sin permiso."
    fi
    for m in \$macs; do
      sudo nft add element inet vmguard vm_inet "{ \$m }" 2>/dev/null || true
      grep -qi "^\$m " "\$ALLOW" 2>/dev/null \\
        || echo "\$m \$vm" | sudo tee -a "\$ALLOW" >/dev/null
    done
    echo "[on]  '\$vm' tiene internet"
    ;;
  off)
    vm="\${2:-}"; [[ -n "\$vm" ]] || { echo "uso: vmnet off <vm>"; exit 1; }
    macs="\$(macs_de "\$vm" || true)"
    if [[ -z "\$macs" ]]; then
      # La VM puede haber desaparecido: se limpia buscando por nombre
      macs="\$(awk -v v="\$vm" '\$2==v{print \$1}' "\$ALLOW" 2>/dev/null || true)"
    fi
    [[ -n "\$macs" ]] || { echo "No encuentro MACs para '\$vm'."; exit 1; }
    for m in \$macs; do
      sudo nft delete element inet vmguard vm_inet "{ \$m }" 2>/dev/null || true
      sudo sed -i "/^\$m /Id" "\$ALLOW" 2>/dev/null || true
    done
    echo "[off] '\$vm' se queda sin internet"
    ;;
  off-all)
    sudo nft flush set inet vmguard vm_inet 2>/dev/null || true
    sudo truncate -s 0 "\$ALLOW" 2>/dev/null || true
    echo "[off] ninguna VM tiene internet"
    ;;
  list|status|"")
    printf '%-28s %-20s %s\\n' "VM" "RED" "INTERNET"
    printf '%-28s %-20s %s\\n' "---------------------------" "-------------------" "--------"
    while read -r vm; do
      [[ -n "\$vm" ]] || continue
      red="\$(redes_de "\$vm" | paste -sd, - || true)"
      estado="no"
      if printf '%s' "\$red" | grep -q "\$NET_FREE"; then
        estado="SI (red libre)"
      else
        for m in \$(macs_de "\$vm" || true); do
          en_set "\$m" && estado="SI"
        done
      fi
      printf '%-28s %-20s %s\\n' "\$vm" "\${red:-?}" "\$estado"
    done < <(sudo virsh list --all --name 2>/dev/null | grep -v '^\$')
    ;;
  *)
    echo "uso: vmnet on|off <vm> | list | off-all"
    exit 1
    ;;
esac
EOF
  sudo chmod 755 "$HELPER"
  state_set HELPER 1
  ok "vmnet on <vm> / vmnet off <vm> / vmnet list"
}

# --- pools ------------------------------------------------------------------
paso_pools() {
  info "Carpetas y pools de almacenamiento"
  mkdir -p "$ISO_DIR" "$DISK_DIR"
  chmod 700 "$VMS_ROOT"
  local pools_new=()

  # libvirt rechaza dos pools sobre la misma carpeta, y virt-manager crea uno
  # con solo navegar a un directorio. Busca por ruta, no por nombre.
  pool_en_ruta() {
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
    local name="$1" path="$2" otro
    otro="$(pool_en_ruta "$path")"
    if [[ -n "$otro" && "$otro" != "$name" ]]; then
      warn "ya hay un pool ('$otro') apuntando a $path"
      warn "lo reutilizo en vez de crear '$name' (libvirt no admite duplicados)"
      sudo virsh pool-autostart "$otro" >/dev/null 2>&1 || true
      sudo virsh pool-start     "$otro" >/dev/null 2>&1 || true
      return 0
    fi
    if sudo virsh pool-info "$name" &>/dev/null; then
      ok "pool '$name' ya existia"
    else
      sudo virsh pool-define-as "$name" dir --target "$path" >/dev/null
      sudo virsh pool-autostart "$name" >/dev/null
      sudo virsh pool-start     "$name" >/dev/null
      pools_new+=("$name")
      ok "pool '$name' -> $path"
    fi
  }
  add_pool "$POOL_ISOS"   "$ISO_DIR"   || warn "no pude preparar el pool de ISOs (sigo)"
  add_pool "$POOL_DISCOS" "$DISK_DIR"  || warn "no pude preparar el pool de discos (sigo)"
  state_set_once POOLS_NEW "${pools_new[*]:-}"
}

# --- QEMU sin privilegios ---------------------------------------------------
# Sin tocar nada, libvirt lanza las VMs de sesion system como root:root.
# Arch crea la cuenta libvirt-qemu pero deja las lineas comentadas.
paso_depriv() {
  info "Quitando el root a QEMU"
  local QCONF=/etc/libvirt/qemu.conf
  sudo test -f "$QCONF" || { warn "no encuentro $QCONF; salto este paso"; return 0; }

  if sudo grep -qE '^(user|group)[[:space:]]*=' "$QCONF"; then
    ok "user/group ya estaban activos en qemu.conf"
  else
    backup_file "$QCONF"
    # Solo las directivas reales: sin sangria y sin comentario a la derecha.
    sudo sed -i -E '/^#(user|group|dynamic_ownership)[[:space:]]*=[^#]*$/ s/^#//' "$QCONF"
    state_set_once QCONF_MODIFIED 1
  fi

  # Filtra las syscalls que QEMU puede pedir al kernel del host
  if ! sudo grep -qE '^seccomp_sandbox[[:space:]]*=' "$QCONF"; then
    backup_file "$QCONF"
    echo 'seccomp_sandbox = 1' | sudo tee -a "$QCONF" >/dev/null
    state_set_once QCONF_MODIFIED 1
    ok "seccomp_sandbox activado"
  fi

  local QUSER QGROUP
  QUSER="$(sudo grep -E '^user[[:space:]]*=' "$QCONF" | head -1 \
           | sed -E 's/^user[[:space:]]*=[[:space:]]*"?([^"[:space:]]*)"?.*/\1/' || true)"
  QGROUP="$(sudo grep -E '^group[[:space:]]*=' "$QCONF" | head -1 \
           | sed -E 's/^group[[:space:]]*=[[:space:]]*"?([^"[:space:]]*)"?.*/\1/' || true)"

  if [[ -z "$QUSER" || -z "$QGROUP" ]] || ! id -u "$QUSER" &>/dev/null; then
    warn "no hay un user/group valido en $QCONF. Descomenta a mano user y group."
    return 0
  fi
  state_set QEMU_USER  "$QUSER"
  state_set QEMU_GROUP "$QGROUP"

  # Transito (--x, sin listar) en las carpetas intermedias; acceso efectivo
  # unicamente a discos e ISOs.
  if command -v setfacl >/dev/null; then
    sudo setfacl    -m "u:${QUSER}:--x" "$HOME"                   2>/dev/null || true
    sudo setfacl    -m "u:${QUSER}:--x" "$VMS_ROOT"               2>/dev/null || true
    sudo setfacl -R -m "u:${QUSER}:rwx" "$ISO_DIR" "$DISK_DIR"    2>/dev/null || true
    sudo setfacl -R -d -m "u:${QUSER}:rwx" "$ISO_DIR" "$DISK_DIR" 2>/dev/null || true
    state_set ACL_APPLIED 1
    ok "ACL: '$QUSER' solo ve tus discos e ISOs, nada mas del HOME"
  else
    warn "falta setfacl; sin ACL las VMs no podran abrir sus discos"
  fi

  if sudo systemctl restart libvirtd.service && systemctl is-active --quiet libvirtd.service; then
    ok "QEMU correra como $QUSER:$QGROUP (ya no root)"
    state_set QEMU_USER_HARDENED 1
  else
    warn "libvirtd no arranca asi -> revirtiendo qemu.conf"
    restore_file "$QCONF"
    sudo systemctl restart libvirtd.service || true
    state_set QEMU_USER_HARDENED 0
  fi
}

# --- AppArmor: linea kernel -------------------------------------------------
paso_apparmor_kernel() {
  apparmor_activo && return 0
  info "Preparando AppArmor en la linea de kernel"
  local lsmstr bl
  lsmstr="$(build_lsm)"
  bl="$(detect_bootloader)"
  state_set BOOTLOADER "$bl"
  case "$bl" in
    grub)         cmdline_grub   "$lsmstr" ;;
    systemd-boot) cmdline_sdboot "$lsmstr" ;;
    uki)          cmdline_uki    "$lsmstr" ;;
    *) warn "no reconozco el gestor de arranque; anade a mano: lsm=$lsmstr" ;;
  esac
}

cmdline_grub() {
  local lsmstr="$1" line val newline
  backup_file /etc/default/grub
  line="$(grep -E '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub | head -1 || true)"
  if [[ -z "$line" ]]; then
    printf 'GRUB_CMDLINE_LINUX_DEFAULT="lsm=%s"\n' "$lsmstr" | sudo tee -a /etc/default/grub >/dev/null
    state_set_once GRUB_CMDLINE_ORIG ""
  else
    state_set_once GRUB_CMDLINE_ORIG "$line"
    val="${line#GRUB_CMDLINE_LINUX_DEFAULT=}"
    val="${val%\"}"; val="${val#\"}"
    val="$(printf '%s' "$val" | sed -E 's/(^| )lsm=[^ ]*//g' | tr -s ' ' | sed -E 's/^ | $//g')"
    newline="GRUB_CMDLINE_LINUX_DEFAULT=\"${val:+$val }lsm=$lsmstr\""
    awk -v new="$newline" '
      /^GRUB_CMDLINE_LINUX_DEFAULT=/ && !d { print new; d=1; next } { print }
    ' /etc/default/grub | sudo tee /etc/default/grub.lab >/dev/null
    sudo mv /etc/default/grub.lab /etc/default/grub
  fi
  state_set GRUB_MODIFIED 1
  sudo grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1 \
    || die "grub-mkconfig fallo. Revisa /etc/default/grub"
  ok "GRUB actualizado con lsm=$lsmstr"
}

cmdline_sdboot() {
  local lsmstr="$1" f
  ensure_dirs
  sudo test -f "$BACKUP_DIR/loader-entries.tar" \
    || sudo tar -cf "$BACKUP_DIR/loader-entries.tar" -C /boot/loader entries
  for f in /boot/loader/entries/*.conf; do
    [[ -e "$f" ]] || continue
    sudo sed -i -E "/^options /{s/(^| )lsm=[^ ]*//g; s/\$/ lsm=$lsmstr/}" "$f"
  done
  state_set SDBOOT_MODIFIED 1
  ok "entradas de systemd-boot actualizadas con lsm=$lsmstr"
}

cmdline_uki() {
  local lsmstr="$1"
  backup_file /etc/kernel/cmdline
  sudo sed -i -E "s/(^| )lsm=[^ ]*//g; s/\$/ lsm=$lsmstr/" /etc/kernel/cmdline
  state_set UKI_MODIFIED 1
  sudo mkinitcpio -P >/dev/null 2>&1 || warn "mkinitcpio fallo; regenera la UKI a mano"
  ok "/etc/kernel/cmdline actualizado con lsm=$lsmstr"
}

# --- perfil AppArmor de QEMU ------------------------------------------------
# AppArmor confina por ruta de ejecutable, de modo que un perfil sobre
# /usr/bin/qemu-system-x86_64 alcanza a cualquier VM sin necesitar soporte en
# libvirt. Arch lo compila con -Dapparmor=disabled, asi que no hay
# virt-aa-helper ni confinamiento por maquina: el perfil es unico y aisla del
# host, no unas VMs de otras.
instalar_perfil_qemu() {
  local QEMU_BIN d_dir i_dir
  QEMU_BIN="$(detect_qemu_bin)" || die "no encuentro qemu-system-x86_64"
  d_dir="$DISK_DIR"; i_dir="$ISO_DIR"

  info "Perfil AppArmor de QEMU (modo registro)"
  backup_file "$QEMU_PROFILE_PATH"
  sudo tee "$QEMU_PROFILE_PATH" > /dev/null <<PROFILE
# Perfil AppArmor compartido por todas las VMs.
# Generado por qemu-secure-lab-1.0.1-ES.sh
#
# Revisar el registro:
#   sudo journalctl -k --since '-2 hours' \\
#     | grep -E 'apparmor="(DENIED|ALLOWED)"' | grep qemu-lab
#
# Devolverlo a modo registro:
#   ./qemu-secure-lab-1.0.1-ES.sh complain

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

  # USB passthrough (Redirector/USB Host Device en virt-manager). Sin esto
  # QEMU no puede enumerar ni abrir el dispositivo aunque libvirt ya le haya
  # dado la propiedad del nodo en /dev.
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

  # Unicas rutas de disco e ISO alcanzables dentro de la carpeta personal
  owner ${d_dir}/*.qcow2 rwk,
  owner ${d_dir}/*.img rwk,
  owner ${d_dir}/*.raw rwk,
  # La k es el permiso de cerrojo. QEMU bloquea tambien el CD-ROM pese a
  # montarlo en solo lectura; sin ella falla con "Failed to lock byte 100".
  owner ${i_dir}/*.iso rk,
}
PROFILE

  sudo apparmor_parser -r "$QEMU_PROFILE_PATH" \
    || die "el perfil no carga. Revisa la sintaxis en $QEMU_PROFILE_PATH"
  state_set QEMU_PROFILE_INSTALLED 1
  state_set QEMU_PROFILE_ENFORCED 0
  marca_complain
  ok "perfil cargado en modo REGISTRO (apunta, todavia no bloquea)"
}

# El fichero del perfil menciona "complain" en su cabecera, asi que buscar esa
# palabra dentro da falsos positivos. Manda lo que el kernel tiene cargado y el
# fichero queda como respaldo.
perfil_en_complain() {
  if sudo test -r /sys/kernel/security/apparmor/profiles; then
    sudo grep -qE '^qemu-lab-qemu \(complain\)' /sys/kernel/security/apparmor/profiles && return 0
    sudo grep -qE '^qemu-lab-qemu \(enforce\)'  /sys/kernel/security/apparmor/profiles && return 1
  fi
  sudo grep -q 'flags=(attach_disconnected,complain)' "$QEMU_PROFILE_PATH" 2>/dev/null
}

# Marca desde cuando revisar el log. Sin acotarlo, arrastra entradas de
# versiones anteriores del perfil que ya estan resueltas.
marca_complain() {
  state_set AA_SINCE "$(date '+%Y-%m-%d %H:%M:%S')"
}

# En modo complain AppArmor registra ALLOWED, no DENIED: anota lo que habria
# bloqueado. Hay que contemplar las dos etiquetas o la revision sale vacia.
denegaciones() {
  local desde
  desde="$(sudo grep -E '^AA_SINCE=' "$STATE_FILE" 2>/dev/null \
           | cut -d= -f2- | tr -d "'\"" || true)"
  [[ -n "$desde" ]] || desde="-2 days"
  sudo journalctl -k --since "$desde" 2>/dev/null \
    | grep -E 'apparmor="(DENIED|ALLOWED)"' | grep -i 'qemu-lab' || true
}

pasar_a_enforce() {
  sudo test -f "$QEMU_PROFILE_PATH" || die "no hay perfil instalado. Lanza: $0"
  if ! perfil_en_complain; then
    ok "el perfil ya estaba en bloqueo real"
    return 0
  fi
  sudo sed -i 's/flags=(attach_disconnected,complain)/flags=(attach_disconnected)/' "$QEMU_PROFILE_PATH"
  sudo apparmor_parser -r "$QEMU_PROFILE_PATH" || die "el perfil no recargo"
  state_set QEMU_PROFILE_ENFORCED 1
  ok "perfil de QEMU en BLOQUEO REAL"
}

pasar_a_complain() {
  sudo test -f "$QEMU_PROFILE_PATH" || die "no hay perfil instalado"
  if perfil_en_complain; then
    ok "el perfil ya estaba en modo registro"
    return 0
  fi
  sudo sed -i 's/flags=(attach_disconnected)/flags=(attach_disconnected,complain)/' "$QEMU_PROFILE_PATH"
  sudo apparmor_parser -r "$QEMU_PROFILE_PATH" || die "el perfil no recargo"
  state_set QEMU_PROFILE_ENFORCED 0
  marca_complain
  ok "perfil de vuelta en modo REGISTRO (apunta, no bloquea)"
}

# --- flujo unico ------------------------------------------------------------
cmd_auto() {
  need_user
  comprobar_estado_previo
  state_set LAB_VERSION "$LAB_VERSION"

  if grep -qE '(^| )mitigations=off( |$)' /proc/cmdline 2>/dev/null; then
    warn "tienes mitigations=off en la linea de kernel: mala idea con VMs"
  fi

  comprobar_firewall
  comprobar_kvm
  detect_iface
  state_set LAB_USER  "$USER"
  state_set IFACE_NET "$IFACE_NET"
  state_set VMS_ROOT  "$VMS_ROOT"

  local vms; vms="$(listar_vms)"
  if [[ -n "$vms" ]]; then
    info "VMs ya definidas (no se tocan)"
    echo "$vms" | sed 's/^/    - /'
  fi

  RELOGIN=0
  paso_paquetes
  paso_servicios
  paso_grupo
  paso_redes
  paso_ufw
  paso_vmguard
  paso_helper
  paso_pools
  paso_depriv

  # AppArmor: el flujo se bifurca segun el LSM este activo o no
  if ! apparmor_activo; then
    paso_apparmor_kernel
    banner_reinicio
    return 0
  fi

  ok "AppArmor activo en el kernel"

  if ! sudo test -f "$QEMU_PROFILE_PATH"; then
    instalar_perfil_qemu
    banner_probar
    return 0
  fi

  if perfil_en_complain; then
    local den
    den="$(denegaciones)"
    if [[ -z "$den" ]]; then
      if [[ -z "$vms" ]]; then
        banner_probar
        warn "aun no tienes ninguna VM definida: creala y vuelve a lanzarme"
        return 0
      fi
      info "Revisando el registro de AppArmor"
      ok "sin denegaciones: paso el perfil a bloqueo real"
      pasar_a_enforce
    else
      info "Revisando el registro de AppArmor"
      warn "hay denegaciones registradas; NO paso a bloqueo real todavia:"
      echo "$den" | tail -20 | sed 's/^/      /'
      echo
      echo "  Cada linea es algo que el perfil bloquearia. Si son rutas tuyas"
      echo "  legitimas, anadelas al final de $QEMU_PROFILE_PATH y relanzame."
      echo "  Si te da igual y quieres bloquear ya:  $0 enforce"
      return 0
    fi
  fi

  banner_final
}

banner_reinicio() {
  cat <<EOF

========================================================================
  PRIMERA PARTE LISTA

  Ya tienes: redes, vmguard, UFW, pools y QEMU sin root.

  FALTA AppArmor, y eso necesita reiniciar (el LSM del kernel no se
  puede encender en caliente).

      sudo reboot
      $0

  Es la misma orden: detecta lo que ya esta hecho y continua.

========================================================================
EOF
  [[ "${RELOGIN:-0}" == "1" ]] && warn "el reinicio tambien arregla lo del grupo libvirt"
  echo
}

banner_probar() {
  cat <<EOF

========================================================================
  CASI

  El perfil de AppArmor esta puesto en modo REGISTRO: apunta lo que
  bloquearia, pero todavia no bloquea nada. Es a proposito: si pasara a
  bloqueo sin haber visto una VM real, se te romperia en el peor momento.

  AHORA:
    1. Crea o arranca una VM y usala un rato (arranca, red, disco, USB...)
    2. Vuelve a lanzar:   $0

  Si el registro sale limpio, el propio script pasa a bloqueo real.

========================================================================
EOF
}

banner_final() {
  info "Estado final"
  echo
  echo "--- Redes ---";   sudo virsh net-list --all
  echo "--- Internet por VM ---"; sudo "$HELPER" list 2>/dev/null || true

  cat <<EOF

========================================================================
  LABORATORIO COMPLETO Y EN BLOQUEO REAL

  ISOs:    $ISO_DIR      (pool '$POOL_ISOS')
  Discos:  $DISK_DIR      (pool '$POOL_DISCOS')

  ELIGE LA RED EN VIRT-MANAGER, EN LA TARJETA DE RED DE CADA VM

    $NET_FREE     sale a internet directamente. Para lo de clase.
    $NET_NAT       igual, pero la salida se concede por maquina.
    $NET_ISO   air gap: sin IP, sin DHCP, el host no esta en ese
                    segmento. IP estatica, p.ej. 10.66.66.0/24

  Las tres bloquean tu LAN, tailnet, zerotier, IPv6, correo y SMB.

  SOLO PARA LAS VMs DE $NET_NAT
    vmnet list                que tiene salida ahora mismo
    vmnet on  <vm>            se la das (al instante, sin reiniciarla)
    vmnet off <vm>            se la quitas

  SI ALGO DEJA DE ARRANCAR
    $0 complain     quita el bloqueo de AppArmor al instante
    $0 verify       comprueba que sigue todo activo

  Para lo peligroso: red '$NET_ISO' y snapshot antes de detonar.
========================================================================

EOF
  [[ "${RELOGIN:-0}" == "1" ]] && warn "CIERRA SESION Y VUELVE A ENTRAR (grupo libvirt)"
  echo
}

# --- STATUS -----------------------------------------------------------------
cmd_status() {
  if ! state_load; then
    echo "El laboratorio no esta instalado (no hay $STATE_FILE)."
    return 0
  fi
  echo "=== qemu-secure-lab ${SCRIPT_VERSION} (estado v${LAB_VERSION:-?}) ==="
  echo "usuario:        ${LAB_USER:-?}"
  echo "interfaz WAN:   ${IFACE_NET:-?}"
  echo "bridge NAT:     ${BR_NAT:-?}  (gw ${BRIDGE_IP:-?})"
  echo "bridge aislado: ${BR_ISO:-?}"
  echo "raiz de VMs:    ${VMS_ROOT:-?}"
  echo "paquetes:       ${PKGS_NEW:-ninguno nuevo}"
  echo "servicios:      ${SVC_NEW:-ninguno nuevo}"
  echo "redes creadas:  ${NETS_NEW:-ninguna}"
  echo "pools creados:  ${POOLS_NEW:-ninguno}"
  echo "QEMU user:      ${QEMU_USER:-root (sin endurecer)}"
  echo "QEMU sin root:  ${QEMU_USER_HARDENED:-0}"
  echo
  echo "--- perfil AppArmor de QEMU ---"
  if sudo test -f "$QEMU_PROFILE_PATH" 2>/dev/null; then
    perfil_en_complain \
      && echo "  instalado, modo REGISTRO (no bloquea)" \
      || echo "  instalado, modo BLOQUEO REAL"
  else
    echo "  no instalado"
  fi
  echo "--- AppArmor kernel ---"
  apparmor_activo && echo "  ACTIVO" || echo "  inactivo (falta reiniciar)"
  echo "--- vmguard ---"
  sudo nft list table inet vmguard >/dev/null 2>&1 && echo "  cargado" || echo "  NO cargado"
  echo
  echo "--- internet por VM ---"
  command -v vmnet >/dev/null && sudo vmnet list || echo "  helper ausente"
}

# --- VERIFY -----------------------------------------------------------------
cmd_verify() {
  need_user
  state_load || true
  local fallos=0
  info "Comprobando lo que esta activo DE VERDAD"

  sudo nft list table inet vmguard >/dev/null 2>&1 \
    && ok "vmguard cargado en el kernel" \
    || { bad "vmguard NO cargado"; fallos=$((fallos+1)); }

  sudo ufw status 2>/dev/null | head -1 | grep -q active \
    && ok "UFW activo" \
    || { bad "UFW no activo"; fallos=$((fallos+1)); }

  apparmor_activo \
    && ok "AppArmor activo en el kernel" \
    || { bad "AppArmor NO activo (falta reiniciar)"; fallos=$((fallos+1)); }

  sudo grep -qE '^user[[:space:]]*=' /etc/libvirt/qemu.conf 2>/dev/null \
    && ok "QEMU no corre como root" \
    || { bad "QEMU correria como root"; fallos=$((fallos+1)); }

  sudo virsh net-info "$NET_ISO" &>/dev/null \
    && ok "red '$NET_ISO' definida" \
    || { bad "falta la red '$NET_ISO'"; fallos=$((fallos+1)); }

  if sudo test -f "$QEMU_PROFILE_PATH"; then
    perfil_en_complain \
      && warn "perfil de QEMU en modo registro (aun no bloquea)" \
      || ok "perfil de QEMU en bloqueo real"
  else
    warn "perfil de QEMU no instalado"
  fi

  # El conjunto de MAC debe existir aunque no tenga elementos
  sudo nft list set inet vmguard vm_inet >/dev/null 2>&1 \
    && ok "control de internet por VM operativo" \
    || { bad "el conjunto vm_inet no existe"; fallos=$((fallos+1)); }

  echo
  ((fallos)) && warn "$fallos comprobacion(es) fallaron" || ok "todo lo critico esta activo"
  cat <<EOF

  Comprobacion manual, con una VM encendida:
    ps -eo user,cmd | grep qemu-system     -> debe poner libvirt-qemu
    sudo aa-status | grep -A2 qemu-lab     -> debe listar el PID

  DESDE DENTRO de una VM de lab-nat sin permiso de internet:
    ip -4 addr              -> debe tener IP ${NAT_SUBNET:-192.168.150}.x (DHCP ok)
    getent hosts debian.org -> NO debe resolver sin permiso de internet
                               (el DNS va por la misma lista blanca que la
                               salida, para cerrar la exfiltracion por DNS)

    ping 1.1.1.1        -> FALLA
    ping 192.168.1.1    -> FALLA (tu router)
    ping 100.64.0.1     -> FALLA (tailnet)
    ping ${BRIDGE_IP:-192.168.150.1}    -> FALLA TAMBIEN, y es correcto:
        al host solo se le permiten DHCP y DNS, el ICMP esta cortado.
        Que el gateway no responda al ping NO significa que no haya red;
        compruebalo con las dos ordenes de arriba.

  Despues de 'vmnet on <vm>', solo 1.1.1.1 debe empezar a responder.
  Los otros dos tienen que seguir fallando. Si responden, avisa.

EOF
}

# --- reversion de configuracion ---------------------------------------------
revertir_config() {
  if command -v ufw >/dev/null; then
    info "Quitando reglas de UFW"
    sudo ufw route delete allow in on "${BR_NAT:-virbr-lab}" out on "${IFACE_NET:-eth0}" >/dev/null 2>&1 || true
    sudo ufw route delete allow in on "${BR_FREE:-virbr-free}" out on "${IFACE_NET:-eth0}" >/dev/null 2>&1 || true
    sudo ufw delete allow in on "${BR_FREE:-virbr-free}" to any port 67 proto udp >/dev/null 2>&1 || true
    sudo ufw delete allow in on "${BR_FREE:-virbr-free}" to "${FREE_IP:-192.168.171.1}" port 53 proto udp >/dev/null 2>&1 || true
    sudo ufw delete allow in on "${BR_FREE:-virbr-free}" to "${FREE_IP:-192.168.171.1}" port 53 proto tcp >/dev/null 2>&1 || true
    sudo ufw delete allow in on "${BR_NAT:-virbr-lab}" to any port 67 proto udp >/dev/null 2>&1 || true
    sudo ufw delete allow in on "${BR_NAT:-virbr-lab}" to "${BRIDGE_IP:-192.168.150.1}" port 53 proto udp >/dev/null 2>&1 || true
    sudo ufw delete allow in on "${BR_NAT:-virbr-lab}" to "${BRIDGE_IP:-192.168.150.1}" port 53 proto tcp >/dev/null 2>&1 || true
    restore_file /etc/default/ufw
    sudo ufw reload >/dev/null 2>&1 || true
    if [[ "${UFW_WAS_ACTIVE:-1}" == "0" ]]; then
      sudo ufw disable >/dev/null 2>&1 || true
      warn "UFW desactivado (estaba asi antes). El equipo queda sin cortafuegos."
    fi
    ok "UFW revertido"
  fi

  info "Quitando vmguard y el mando de internet"
  sudo systemctl disable --now vmguard.service >/dev/null 2>&1 || true
  sudo rm -f /etc/systemd/system/vmguard.service "$NFT_FILE" "$LOADER" "$HELPER"
  sudo rmdir /etc/nftables.d 2>/dev/null || true
  sudo systemctl daemon-reload
  sudo nft delete table inet vmguard >/dev/null 2>&1 || true
  ok "vmguard y vmnet eliminados"

  local n
  if [[ -n "${POOLS_NEW:-}" ]]; then
    info "Quitando pools creados por el script (los ficheros NO se borran)"
    for n in ${POOLS_NEW}; do
      sudo virsh pool-destroy  "$n" >/dev/null 2>&1 || true
      sudo virsh pool-undefine "$n" >/dev/null 2>&1 || true
      ok "pool '$n' eliminado"
    done
  fi
  if [[ -n "${NETS_NEW:-}" ]]; then
    info "Quitando redes creadas por el script"
    for n in ${NETS_NEW}; do
      sudo virsh net-destroy  "$n" >/dev/null 2>&1 || true
      sudo virsh net-undefine "$n" >/dev/null 2>&1 || true
      ok "red '$n' eliminada"
    done
  fi

  if sudo test -f "$QEMU_PROFILE_PATH" 2>/dev/null; then
    info "Quitando el perfil AppArmor de QEMU"
    sudo apparmor_parser -R "$QEMU_PROFILE_PATH" >/dev/null 2>&1 || true
    sudo rm -f "$QEMU_PROFILE_PATH"
    ok "perfil eliminado"
  fi

  if [[ "${ACL_APPLIED:-0}" == "1" ]] && command -v setfacl >/dev/null; then
    info "Quitando ACL de '${QEMU_USER:-libvirt-qemu}'"
    local qu="${QEMU_USER:-libvirt-qemu}" vroot="${VMS_ROOT:-$HOME/VMs}"
    sudo setfacl    -x "u:${qu}" "$HOME"                        2>/dev/null || true
    sudo setfacl    -x "u:${qu}" "$vroot"                       2>/dev/null || true
    sudo setfacl -R -x "u:${qu}" "$vroot/ISOs" "$vroot/QEMU"    2>/dev/null || true
    sudo setfacl -R -d -x "u:${qu}" "$vroot/ISOs" "$vroot/QEMU" 2>/dev/null || true
    ok "ACL retiradas"
  fi
  if [[ "${QCONF_MODIFIED:-0}" == "1" ]]; then
    info "Revirtiendo qemu.conf"
    restore_file /etc/libvirt/qemu.conf
    sudo systemctl restart libvirtd.service >/dev/null 2>&1 || true
  fi

  if [[ "${GRUB_MODIFIED:-0}" == "1" ]]; then
    info "Restaurando la linea de kernel en GRUB"
    if [[ -n "${GRUB_CMDLINE_ORIG:-}" ]]; then
      awk -v old="$GRUB_CMDLINE_ORIG" '
        /^GRUB_CMDLINE_LINUX_DEFAULT=/ && !d { print old; d=1; next } { print }
      ' /etc/default/grub | sudo tee /etc/default/grub.lab >/dev/null
      sudo mv /etc/default/grub.lab /etc/default/grub
    else
      restore_file /etc/default/grub
    fi
    sudo grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1 || warn "grub-mkconfig fallo"
    ok "GRUB restaurado (efectivo tras reiniciar)"
  fi
  if [[ "${SDBOOT_MODIFIED:-0}" == "1" ]] && sudo test -f "$BACKUP_DIR/loader-entries.tar"; then
    sudo tar -xf "$BACKUP_DIR/loader-entries.tar" -C /boot/loader
    ok "entradas de systemd-boot restauradas"
  fi
  if [[ "${UKI_MODIFIED:-0}" == "1" ]]; then
    restore_file /etc/kernel/cmdline
    sudo mkinitcpio -P >/dev/null 2>&1 || warn "mkinitcpio fallo"
  fi
  if [[ "${AA_SVC_ENABLED_BY_US:-0}" == "1" ]]; then
    sudo systemctl disable --now apparmor.service >/dev/null 2>&1 || true
    ok "apparmor.service deshabilitado"
  fi

  if [[ "${GROUP_ADDED:-0}" == "1" ]]; then
    sudo gpasswd -d "${LAB_USER:-$USER}" libvirt >/dev/null 2>&1 || true
    ok "usuario sacado del grupo libvirt"
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

  state_load || warn "no hay estado previo; hare limpieza a ciegas de lo conocido"

  local vms vroot
  vms="$(listar_vms)"
  vroot="${VMS_ROOT:-$HOME/VMs}"

  echo
  if ((soft)); then
    echo "  UNINSTALL --soft: revierte la configuracion, deja qemu instalado."
  else
    echo "  UNINSTALL: deja el equipo como si nunca hubieras instalado esto."
    echo "  Se revierte la configuracion Y se desinstalan:"
    echo "      ${PKGS_PURGE[*]}"
    echo "  (nunca se tocan: ${PKGS_PROTEGIDOS[*]} y apparmor)"
  fi
  echo
  echo "  NO SE BORRA NINGUN FICHERO TUYO:"
  echo "    - discos e ISOs en $vroot"
  echo "    - definiciones de VMs en /etc/libvirt/qemu/"
  if [[ -n "$vms" ]]; then
    echo
    warn "tienes VMs definidas:"
    echo "$vms" | sed 's/^/        - /'
    ((soft)) || warn "tras el uninstall no arrancaran hasta que reinstales qemu"
  fi
  echo
  if ! ((yes)); then
    local resp
    read -r -p "  Escribe SI para continuar: " resp || resp=""
    [[ "$resp" == "SI" ]] || { echo "Cancelado."; return 0; }
  fi

  revertir_config

  if ! ((soft)); then
    info "Parando servicios de libvirt"
    local s
    for s in libvirtd.service libvirtd.socket virtlogd.service virtlogd.socket; do
      sudo systemctl disable --now "$s" >/dev/null 2>&1 || true
    done
    ok "servicios parados"

    local a_borrar=() p prot skip
    for p in "${PKGS_PURGE[@]}"; do
      pacman -Qq "$p" &>/dev/null || continue
      skip=0
      for prot in "${PKGS_PROTEGIDOS[@]}"; do [[ "$p" == "$prot" ]] && skip=1; done
      ((skip)) || a_borrar+=("$p")
    done
    if ((${#a_borrar[@]})); then
      info "Desinstalando: ${a_borrar[*]}"
      sudo pacman -Rns --noconfirm "${a_borrar[@]}" \
        || warn "pacman no pudo quitar todo (dependencias). Revisalo a mano."
    else
      ok "no habia paquetes del laboratorio instalados"
    fi
  fi

  sudo rm -rf "$STATE_DIR"
  ok "estado eliminado"

  cat <<EOF

========================================================================
  DESINSTALADO

  SIGUEN AHI (son tuyos, borralos tu si quieres):
    $vroot                    discos .qcow2 e ISOs
    /etc/libvirt/qemu/*.xml   definiciones de VMs

  Si se toco la linea de kernel, REINICIA para completar la reversion.
========================================================================

EOF
}

# --- main -------------------------------------------------------------------
case "${1:-}" in
  ""|install|--install)  cmd_auto ;;
  status)                cmd_status ;;
  verify)                cmd_verify ;;
  enforce)               need_user; pasar_a_enforce ;;
  complain)              need_user; pasar_a_complain ;;
  uninstall|purge)       shift; cmd_uninstall "$@" ;;
  -h|--help|help)
    cat <<EOF
qemu-secure-lab-1.0.1-ES.sh $SCRIPT_VERSION
Laboratorio QEMU/KVM endurecido para Arch Linux.

  $0 [orden]

  (sin orden)       instala y avanza; se puede repetir sin riesgo
  status            configuracion registrada
  verify            comprueba que esta activo de verdad
  enforce           bloqueo real de AppArmor ya
  complain          vuelve a modo registro (si algo deja de arrancar)
  uninstall         deja el equipo como antes (tambien quita qemu)
  uninstall --soft  revierte la configuracion, deja qemu instalado

Internet por maquina, una vez instalado:
  vmnet list | vmnet on <vm> | vmnet off <vm> | vmnet off-all

Nunca borra tus VMs, discos ni ISOs.
Variables: IFACE_NET, VMS_ROOT
EOF
    ;;
  *) die "Comando desconocido: $1   (prueba: $0 --help)" ;;
esac
