# qemu-secure-lab

**Laboratorio QEMU/KVM endurecido para Arch Linux · Hardened QEMU/KVM lab for Arch Linux**

[Español](#español) · [English](#english)

Dos ediciones del mismo script. Cambia el idioma de los mensajes y el nombre de
las redes; las reglas son idénticas.
Two editions of the same script. Message language and network names differ; the
rules are identical.

| | Script | Redes / Networks |
|---|---|---|
| Español | `qemu-secure-lab-1.0.0.sh` | `lab-libre` · `lab-nat` · `lab-aislada` |
| English | `qemu-secure-lab-1.0.0-EN.sh` | `lab-open` · `lab-nat` · `lab-isolated` |

> **No instales las dos.** Comparten fichero de estado, tabla nftables, helper y
> perfil AppArmor. La edición inglesa aborta si detecta la española.
>
> **Do not install both.** They share the same state file, nftables table,
> helper and AppArmor profile. The English edition aborts if it finds the
> Spanish one.

> **Sin garantía. Software publicado tal cual, bajo tu propia responsabilidad.**
> Ver [aviso de responsabilidad](#aviso-de-responsabilidad).
>
> **No warranty. Provided as is, use at your own risk.**
> See [disclaimer](#disclaimer).

---

<a name="español"></a>

# Español

Laboratorio QEMU/KVM endurecido para Arch Linux, en un solo script.

Levanta un entorno de virtualización para prácticas de seguridad: QEMU sin
privilegios, perfil AppArmor propio, tres redes con distinto grado de
aislamiento y salida a internet controlada. Todo reversible.

> **Sin garantía de ningún tipo.** Modifica el cortafuegos, la línea de arranque
> del kernel y la configuración de libvirt. Léete el
> [aviso de responsabilidad](#aviso-de-responsabilidad) antes de ejecutarlo.

---

## Para qué sirve

- Prácticas de ciclos de ciberseguridad y administración de sistemas
- Máquinas vulnerables de laboratorio (Metasploitable, DVWA y similares)
- Analizar comportamiento de software sin que toque la red de casa
- Aislar VMs de la LAN, de Tailscale, de ZeroTier y del propio host

**No sirve** para detonar malware real y dirigido. Ver
[De qué no protege](#de-qué-no-protege).

---

## Requisitos

| | |
|---|---|
| Distribución | Arch Linux |
| CPU | VT-x o AMD-V activo en BIOS/UEFI |
| Cortafuegos | UFW (aborta si detecta firewalld) |
| Otros | systemd, sudo |

---

## Instalación

```bash
chmod +x qemu-secure-lab-1.0.0.sh
./qemu-secure-lab-1.0.0.sh
```

Se ejecuta varias veces. Cada pasada avanza desde donde quedó la anterior y no
rehace lo ya hecho.

| Pasada | Qué hace |
|---|---|
| 1ª | Paquetes, redes, cortafuegos, pools, QEMU sin root. Pide reiniciar |
| 2ª | Carga el perfil AppArmor en modo registro |
| 3ª | Revisa el registro y pasa a bloqueo si está limpio |

El reinicio es obligatorio: AppArmor se habilita en la línea de kernel y no
admite carga en caliente.

---

## Uso

La salida a internet se elige cambiando la red de la VM en virt-manager
(*Tarjeta de red → Origen de red*). No hace falta ninguna orden.

| Red | DHCP | Internet | Uso |
|---|---|---|---|
| `lab-libre` | sí | directa | día a día |
| `lab-nat` | sí | por autorización | VMs que no controlas |
| `lab-aislada` | **no** | ninguna | air gap |

`lab-aislada` no tiene DHCP ni dirección del host en el segmento: hay que
poner IP estática dentro del invitado (p. ej. `10.66.66.10/24`, sin gateway).

Las subredes se eligen solas entre varias candidatas, evitando las que ya
estén en uso en el equipo. Por defecto `192.168.150.0/24` y `192.168.171.0/24`.

### Autorizar salida en `lab-nat`

```bash
vmnet list          # estado de cada VM
vmnet on  <vm>      # concede salida
vmnet off <vm>      # la retira
vmnet off-all       # corta a todas
```

Se aplica sobre la MAC en caliente, sin reiniciar la VM, y persiste entre
arranques del host. Retirar el permiso quita también la resolución DNS.

### Otras órdenes

```
status            configuración registrada
verify            comprueba qué está activo en el kernel
enforce           fuerza el bloqueo de AppArmor
complain          devuelve el perfil a modo registro
uninstall         revierte todo y desinstala los paquetes
uninstall --soft  revierte solo la configuración
```

`uninstall` no toca discos, ISOs ni definiciones de VM.

---

## Capas de seguridad

| Capa | Mecanismo | Detiene |
|---|---|---|
| Hardware | VT-x/AMD-V, kernel propio por VM | Escaladas del kernel invitado |
| Proceso | QEMU como `libvirt-qemu`, seccomp | Acceso al host tras un escape |
| MAC | Perfil AppArmor sobre el binario | Lectura de rutas fuera del lab |
| Red | nftables `vmguard` (prioridad −10) | LAN, VPN, IPv6, correo, SMB |
| Ficheros | ACL POSIX sobre `$HOME` | Acceso al resto de la carpeta |

### Bloqueado en las tres redes

```
10.0.0.0/8  172.16.0.0/12  192.168.0.0/16    redes privadas
100.64.0.0/10                                CGNAT / Tailscale
127.0.0.0/8  169.254.0.0/16  224.0.0.0/4     loopback, link-local, multicast
IPv6 completo
25, 465, 587, 2525                           correo saliente
135, 137-139, 445, 3389                      SMB, NetBIOS, RPC, RDP
```

Además: nadie de fuera abre conexiones hacia una VM, no se cruza de una red
del laboratorio a otra, y del host solo se alcanzan DHCP y DNS del propio
bridge.

---

## Qué desactivar a mano

virt-manager añade por defecto dispositivos que **anulan buena parte del
aislamiento**. El script no los toca porque son ajustes por máquina. Con la VM
apagada, elimínalos desde el panel de hardware:

| Dispositivo | Riesgo |
|---|---|
| Canal (spice) | Portapapeles compartido y arrastrar-soltar |
| Redireccionador USB 1 y 2 | Paso de USB del host |
| Sistema de archivos | Acceso directo a una carpeta del host |

Comprobar que están fuera:

```bash
sudo virsh dumpxml <vm> | grep -E 'spicevmc|redirdev|filesystem'
```

Salida vacía = limpio. `Canal (qemu-ga)` puede quedarse: no comparte nada.

---

## De qué no protege

- **Malware real y dirigido.** Los escapes de QEMU existen y aparecen con
  regularidad. Para eso hace falta hardware dedicado y desconectado.
- **Canales laterales** tipo Spectre y ataques a firmware.
- **Lo que actives tú.** Carpeta compartida, portapapeles o USB pasan por
  encima de todas las capas.
- **Redes en modo bridge o macvtap.** No pasan por estas reglas. Macvtap
  además esquiva el netfilter del host por completo.

---

## Limitaciones conocidas

- **Perfil AppArmor único.** Arch compila libvirt sin `virt-aa-helper`, así
  que no hay confinamiento por máquina: el perfil aísla del host, no unas VMs
  de otras.
- **Las VMs de una misma red se ven entre sí.** Es deliberado, hace falta para
  las prácticas de varias máquinas. Si una cae, alcanza a sus vecinas.
- **Suplantación de MAC.** Una VM de `lab-nat` puede tomar la MAC de otra
  autorizada y heredar su salida. Se cierra añadiendo
  `<filterref filter='clean-traffic'/>` a la interfaz en el XML.
- **`lab-libre` sale desde el primer arranque.** Es cómodo, pero pierde la red
  de seguridad de "por defecto no sale nada".
- **Una VM en `lab-nat` sin permiso tampoco resuelve nombres.** Es a propósito,
  cierra la exfiltración por consultas DNS. `apt` fallará por DNS, no por red.

---

## Si algo deja de arrancar

Casi siempre es AppArmor bloqueando una ruta nueva (USB, carpeta compartida,
un disco fuera de `~/VMs/QEMU`, instantáneas externas).

```bash
./qemu-secure-lab-1.0.0.sh complain
sudo journalctl -k --since '-5 min' \
  | grep -E 'apparmor="(DENIED|ALLOWED)"' | grep qemu-lab
```

Añade las rutas legítimas al final de
`/etc/apparmor.d/qemu-lab.qemu-system-x86_64` y vuelve a lanzar el script.
`aa-logprof` hace lo mismo de forma interactiva.

---

## Desinstalación

```bash
./qemu-secure-lab-1.0.0.sh uninstall
```

Revierte cortafuegos, redes, pools, ACL, perfil AppArmor y línea de kernel, y
desinstala los paquetes del laboratorio. Nunca borra discos `.qcow2`, ISOs ni
definiciones de VM. Con `--soft` deja QEMU instalado.

Si se tocó la línea de kernel, hay que reiniciar para completar la reversión.

---

## Aviso de responsabilidad

Proyecto personal, publicado tal cual, sin garantía y sin auditoría de
seguridad independiente.

- **Lo ejecutas bajo tu responsabilidad.** El autor no responde de daños en el
  sistema, pérdida de datos, caídas de red ni de ninguna consecuencia derivada
  de usar este script.
- **Toca partes críticas del sistema**: reglas de cortafuegos, línea de arranque
  del kernel, configuración de libvirt, permisos del directorio personal y
  perfiles de AppArmor. Lee el código antes de lanzarlo y haz copia de lo que
  te importe.
- **El aislamiento no es absoluto.** Los escapes de máquina virtual existen. El
  autor no responde de un compromiso del equipo anfitrión, de la red local o de
  terceros a raíz de software ejecutado dentro de una VM.
- **No lo uses para malware real y dirigido.** Eso exige hardware dedicado y
  desconectado. Ver [De qué no protege](#de-qué-no-protege).
- **Cúmplelo todo dentro de la ley.** Ejecuta software y pruebas ofensivas solo
  sobre sistemas de tu propiedad o con autorización expresa por escrito. La
  tenencia, distribución y ejecución de código malicioso están reguladas y
  varían según el país. El uso que le des es responsabilidad tuya.
- **Sin soporte ni compromiso de mantenimiento.** Los informes de fallo se
  agradecen, pero no hay garantía de respuesta ni de corrección.

Usar este script implica aceptar lo anterior.

---

## Licencia

MIT

---

<a name="english"></a>

# English

Hardened QEMU/KVM lab for Arch Linux, in a single script.

Sets up a virtualisation environment for security practice: unprivileged QEMU,
a dedicated AppArmor profile, three networks with different isolation levels
and controlled internet access. Fully reversible.

> Script output and inline comments are in Spanish.

> **No warranty of any kind.** It modifies your firewall, kernel command line
> and libvirt configuration. Read the [disclaimer](#disclaimer) before running
> it.

---

## What it is for

- Cybersecurity and sysadmin coursework
- Deliberately vulnerable lab machines (Metasploitable, DVWA and the like)
- Observing software behaviour without letting it reach your home network
- Keeping VMs away from the LAN, Tailscale, ZeroTier and the host itself

**Not** for detonating real, targeted malware. See
[What it does not protect against](#what-it-does-not-protect-against).

---

## Requirements

| | |
|---|---|
| Distribution | Arch Linux |
| CPU | VT-x or AMD-V enabled in BIOS/UEFI |
| Firewall | UFW (aborts if firewalld is running) |
| Other | systemd, sudo |

---

## Install

```bash
chmod +x qemu-secure-lab-1.0.0-EN.sh
./qemu-secure-lab-1.0.0-EN.sh
```

Run it more than once. Each pass picks up where the last one stopped and never
redoes finished work.

| Pass | What happens |
|---|---|
| 1st | Packages, networks, firewall, pools, QEMU deprivileged. Asks for a reboot |
| 2nd | Loads the AppArmor profile in complain mode |
| 3rd | Reviews the log and switches to enforce if it is clean |

The reboot is not optional: AppArmor is enabled on the kernel command line and
cannot be loaded at runtime.

---

## Usage

Internet access is chosen by switching the VM's network in virt-manager
(*NIC → Network source*). No commands involved.

| Network | DHCP | Internet | Use |
|---|---|---|---|
| `lab-open` | yes | direct | everyday work |
| `lab-nat` | yes | per-VM allowlist | VMs you do not control |
| `lab-isolated` | **no** | none | air gap |

`lab-isolated` has no DHCP and no host address on the segment: set a static IP
inside the guest (e.g. `10.66.66.10/24`, no gateway).

Subnets are picked automatically from a candidate list, skipping any already
in use on the machine. Defaults are `192.168.150.0/24` and `192.168.171.0/24`.

### Granting access on `lab-nat`

```bash
vmnet list          # status of every VM
vmnet on  <vm>      # grant outbound access
vmnet off <vm>      # revoke it
vmnet off-all       # cut everyone off
```

Applied to the MAC at runtime, no VM restart, and it survives host reboots.
Revoking access also removes DNS resolution.

### Other commands

```
status            recorded configuration
verify            checks what is actually active in the kernel
enforce           force AppArmor into enforce mode
complain          put the profile back into complain mode
uninstall         revert everything and remove the packages
uninstall --soft  revert configuration only
```

`uninstall` never touches disks, ISOs or VM definitions.

---

## Security layers

| Layer | Mechanism | Stops |
|---|---|---|
| Hardware | VT-x/AMD-V, separate kernel per VM | Guest kernel escalation |
| Process | QEMU as `libvirt-qemu`, seccomp | Host access after an escape |
| MAC | AppArmor profile on the binary | Reading paths outside the lab |
| Network | nftables `vmguard` (priority −10) | LAN, VPN, IPv6, mail, SMB |
| Files | POSIX ACLs on `$HOME` | Access to the rest of your home |

### Blocked on all three networks

```
10.0.0.0/8  172.16.0.0/12  192.168.0.0/16    private ranges
100.64.0.0/10                                CGNAT / Tailscale
127.0.0.0/8  169.254.0.0/16  224.0.0.0/4     loopback, link-local, multicast
all of IPv6
25, 465, 587, 2525                           outbound mail
135, 137-139, 445, 3389                      SMB, NetBIOS, RPC, RDP
```

On top of that: nothing outside can open a connection towards a VM, traffic
cannot cross between lab networks, and only DHCP and DNS on the VM's own
bridge are reachable on the host.

---

## Turn these off by hand

virt-manager adds devices by default that **defeat much of the isolation**.
The script leaves them alone because they are per-VM settings. With the VM
shut down, remove them from the hardware panel:

| Device | Risk |
|---|---|
| Channel spice | Shared clipboard and drag-and-drop |
| USB Redirector 1 and 2 | Host USB passthrough |
| Filesystem | Direct access to a host directory |

Confirm they are gone:

```bash
sudo virsh dumpxml <vm> | grep -E 'spicevmc|redirdev|filesystem'
```

Empty output means clean. `Channel qemu-ga` can stay: it shares nothing.

---

## What it does not protect against

- **Real, targeted malware.** QEMU escapes exist and show up regularly. That
  calls for dedicated, disconnected hardware.
- **Side channels** such as Spectre, and firmware attacks.
- **Anything you enable yourself.** A shared folder, clipboard or USB
  passthrough bypasses every layer above.
- **Bridged or macvtap networking.** Neither goes through these rules, and
  macvtap skips host netfilter entirely.

---

## Known limitations

- **Single AppArmor profile.** Arch builds libvirt without `virt-aa-helper`,
  so there is no per-VM confinement: the profile isolates from the host, not
  VMs from each other.
- **VMs on the same network can see each other.** Deliberate, since
  multi-machine exercises need it. If one falls, it reaches its neighbours.
- **MAC spoofing.** A `lab-nat` VM can take an authorised VM's MAC and inherit
  its access. Close it by adding `<filterref filter='clean-traffic'/>` to the
  interface in the VM's XML.
- **`lab-open` has access from first boot.** Convenient, but it loses the
  "nothing gets out unless you say so" default.
- **A `lab-nat` VM without access cannot resolve names either.** Deliberate,
  it closes DNS-based exfiltration. `apt` will fail on DNS, not on routing.

---

## When a VM stops booting

It is almost always AppArmor blocking a new path (USB, shared folder, a disk
outside `~/VMs/QEMU`, external snapshots).

```bash
./qemu-secure-lab-1.0.0-EN.sh complain
sudo journalctl -k --since '-5 min' \
  | grep -E 'apparmor="(DENIED|ALLOWED)"' | grep qemu-lab
```

Add the legitimate paths to the end of
`/etc/apparmor.d/qemu-lab.qemu-system-x86_64` and run the script again.
`aa-logprof` does the same thing interactively.

---

## Uninstall

```bash
./qemu-secure-lab-1.0.0-EN.sh uninstall
```

Reverts firewall, networks, pools, ACLs, AppArmor profile and kernel command
line, then removes the lab packages. It never deletes `.qcow2` disks, ISOs or
VM definitions. Use `--soft` to keep QEMU installed.

Reboot to finish the revert if the kernel command line was modified.

---

## Disclaimer

Personal project, published as is, with no warranty and no independent security
audit.

- **You run it at your own risk.** The author is not liable for system damage,
  data loss, network outages or any other consequence of using this script.
- **It touches critical parts of the system**: firewall rules, the kernel
  command line, libvirt configuration, home directory permissions and AppArmor
  profiles. Read the code before running it and back up anything you care about.
- **Isolation is not absolute.** VM escapes exist. The author is not liable for
  compromise of the host, the local network or third parties resulting from
  software run inside a VM.
- **Do not use it for real, targeted malware.** That calls for dedicated,
  disconnected hardware. See
  [What it does not protect against](#what-it-does-not-protect-against).
- **Stay within the law.** Only run software and offensive testing against
  systems you own or have explicit written authorisation for. Possession,
  distribution and execution of malicious code are regulated and the rules vary
  by country. How you use this tool is your responsibility.
- **No support and no maintenance commitment.** Bug reports are welcome, but
  there is no guarantee of a reply or a fix.

Using this script means accepting the above.

---

## Licence

MIT
