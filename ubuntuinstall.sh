#!/bin/bash

set -eu

err() {
    printf "\nError: %s.\n" "$1" 1>&2
    exit 1
}

warn() {
    printf "\nWarning: %s.\nContinuando com o padrão...\n" "$1" 1>&2
    sleep 5
}

command_exists() {
    command -v "$1" > /dev/null 2>&1
}

in_target_script=
in_target() {
    local command=
    for argument in "$@"; do
        command="$command $argument"
    done
    if [ -n "$command" ]; then
        [ -z "$in_target_script" ] && in_target_script='true'
        in_target_script="$in_target_script;$command"
    fi
}

in_target_backup() {
    in_target "if [ ! -e \"$1.backup\" ]; then cp \"$1\" \"$1.backup\"; fi"
}

configure_sshd() {
    [ -z "${sshd_config_backup+1s}" ] && in_target_backup /etc/ssh/sshd_config
    sshd_config_backup=
    in_target sed -Ei \""s/^#?$1 .+/$1 $2/"\" /etc/ssh/sshd_config
}

prompt_password() {
    local prompt=
    if [ $# -gt 0 ]; then
        prompt=$1
    elif [ "$username" = root ]; then
        echo -e "\033[1;31m═══════════════════════════════════════════════\033[0m"
        tput setaf 8 ; tput setab 4 ; tput bold ; printf '%33s%s%-14s\n' "DEFINIR A SENHA ROOT" ; tput sgr0
        echo -e "\033[1;31m═══════════════════════════════════════════════\033[0m"
        prompt="Senha do usuário root: "
    else
        echo -e "\033[1;31m═══════════════════════════════════════════════\033[0m"
        tput setaf 8 ; tput setab 4 ; tput bold ; printf '%33s%s%-14s\n' "DEFINIR A SENHA DO USUÁRIO" ; tput sgr0
        echo -e "\033[1;31m═══════════════════════════════════════════════\033[0m"
        prompt="Senha do usuário $username: "
    fi
    while true; do
        echo -ne "\n\033[1;33m$prompt\033[0m"
        read -r password
        if [ -z "$password" ]; then
            echo -e "\033[1;31mSenha não pode estar vazia.\033[0m"
        elif [ "${#password}" -lt 8 ]; then
            echo -e "\033[1;31mSenha deve ter pelo menos 8 caracteres.\033[0m"
        else
            break
        fi
    done
}

download() {
    [ -n "$mirror_proxy" ] &&
    [ -z "${http_proxy+1s}" ] &&
    [ -z "${https_proxy+1s}" ] &&
    [ -z "${ftp_proxy+1s}" ] &&
    export http_proxy="$mirror_proxy" &&
    export https_proxy="$mirror_proxy" &&
    export ftp_proxy="$mirror_proxy"
    if command_exists wget; then
        wget -O "$2" "$1"
    elif command_exists curl; then
        curl -fL "$1" -o "$2"
    elif command_exists busybox && busybox wget --help > /dev/null 2>&1; then
        busybox wget -O "$2" "$1"
    else
        err 'Não é possível encontrar “wget”, “curl” ou “busybox wget” para baixar arquivos'
    fi
}

set_mirror_proxy() {
    [ -n "$mirror_proxy" ] && return
    case $mirror_protocol in
        http) [ -n "${http_proxy+1s}" ] && mirror_proxy="$http_proxy" ;;
        https) [ -n "${https_proxy+1s}" ] && mirror_proxy="$https_proxy" ;;
        ftp) [ -n "${ftp_proxy+1s}" ] && mirror_proxy="$ftp_proxy" ;;
        *) err "Protocolo não suportado: $mirror_protocol" ;;
    esac
}

set_security_archive() {
    if [ "$distro" = "debian" ]; then
        case $suite in
            buster|oldoldstable) security_archive="$suite/updates" ;;
            bullseye|oldstable|bookworm|stable|trixie|testing) security_archive="$suite-security" ;;
            sid|unstable) security_archive='' ;;
            *) err "Suite não suportada: $suite" ;;
        esac
    elif [ "$distro" = "ubuntu" ]; then
        security_archive="$suite-security"
    fi
}

set_daily_d_i() {
    if [ "$distro" = "debian" ]; then
        case $suite in
            buster|oldoldstable|bullseye|oldstable|bookworm|stable) daily_d_i=false ;;
            trixie|testing|sid|unstable) daily_d_i=true ;;
            *) err "Suite não suportada: $suite" ;;
        esac
    else
        daily_d_i=false
    fi
}

set_distro_version() {
    case $1 in
        10|buster) distro=debian; suite=buster ;;
        11|bullseye) distro=debian; suite=bullseye ;;
        12|bookworm) distro=debian; suite=bookworm ;;
        13|trixie) distro=debian; suite=trixie ;;
        14.04|trusty) distro=ubuntu; suite=trusty ;;
        16.04|xenial) distro=ubuntu; suite=xenial ;;
        18.04|bionic) distro=ubuntu; suite=bionic ;;
        20.04|focal) distro=ubuntu; suite=focal ;;
        22.04|jammy) distro=ubuntu; suite=jammy ;;
        24.04|noble) distro=ubuntu; suite=noble ;;
        *) err "Versão não suportada: $1" ;;
    esac
    set_daily_d_i
    set_security_archive
}

has_cloud_kernel() {
    if [ "$distro" = "debian" ]; then
        case $suite in
            buster|oldoldstable)
                [ "$architecture" = amd64 ] && return
                [ "$architecture" = arm64 ] && [ "$bpo_kernel" = true ] && return
                ;;
            bullseye|oldstable|bookworm|stable|trixie|testing|sid|unstable)
                [ "$architecture" = amd64 ] || [ "$architecture" = arm64 ] && return
                ;;
        esac
        local tmp; tmp=''; [ "$bpo_kernel" = true ] && tmp='-backports'
        warn "Nenhum kernel de nuvem disponível para $architecture/$suite$tmp"
        return 1
    else
        return 0
    fi
}

has_backports() {
    if [ "$distro" = "debian" ]; then
        case $suite in
            buster|oldoldstable|bullseye|oldstable|bookworm|stable|trixie|testing) return ;;
        esac
        warn "Nenhum backport disponível para $suite"
        return 1
    else
        return 1
    fi
}

distro_version=11
while true; do
    clear
    echo -e "\033[1;31m═══════════════════════════════════════════════\033[0m"
    tput setaf 8 ; tput setab 4 ; tput bold ; printf '%36s%s%-12s\n' "ESCOLHA A VERSÃO DA DISTRIBUIÇÃO" ; tput sgr0
    echo -e "\033[1;31m═══════════════════════════════════════════════\033[0m"
    echo -e "\033[1;32mRecomenda-se Debian 11 ou Ubuntu 20.04.\033[0m"
    echo -ne "Escolha (10, 11, 12, 13 para Debian; 14.04, 16.04, 18.04, 20.04, 22.04, 24.04 para Ubuntu) [Padrão: 11]: "
    read -r user_input
    distro_version=${user_input:-$distro_version}
    if [[ "$distro_version" =~ ^(10|11|12|13|14.04|16.04|18.04|20.04|22.04|24.04|buster|bullseye|bookworm|trixie|trusty|xenial|bionic|focal|jammy|noble)$ ]]; then
        set_distro_version "$distro_version"
        break
    else
        err "Versão não suportada: $distro_version"
    fi
done

if [ "$distro" = "debian" ]; then
    mirror_host=deb.debian.org
    mirror_directory=/debian
elif [ "$distro" = "ubuntu" ]; then
    mirror_host=archive.ubuntu.com
    mirror_directory=/ubuntu
fi

interface=auto
ip=
netmask=
gateway=
dns='1.1.1.1 8.8.8.8'
dns6='2606:4700:4700::1111 2001:4860:4860::8888'
hostname=
network_console=false
mirror_protocol=https
mirror_proxy=
security_repository=mirror
account_setup=true
username=root
password=
authorized_keys_url=
sudo_with_password=false
timezone=UTC-3
ntp=time.google.com
disk_partitioning=true
disk="/dev/$(lsblk -no PKNAME "$(df /boot | grep -Eo '/dev/[a-z0-9]+')")"
force_gpt=true
efi=
esp=106
filesystem=ext4
kernel=
cloud_kernel=false
bpo_kernel=false
install_recommends=true
install=
upgrade=
kernel_params=
force_lowmem=
bbr=false
ssh_port=
hold=false
power_off=false
architecture=
firmware=false
force_efi_extra_removable=true
grub_timeout=5
dry_run=false
apt_non_free_firmware=true
apt_non_free=false
apt_contrib=false
apt_src=true
apt_backports=true
cidata=

while [ $# -gt 0 ]; do
    case $1 in
        --cdn) ;;
        --aws) mirror_host=cdn-aws.deb.debian.org; ntp=time.aws.com ;;
        --cloudflare) dns='1.1.1.1 1.0.0.1'; dns6='2606:4700:4700::1111 2606:4700:4700::1001'; ntp=time.cloudflare.com ;;
        --aliyun) dns='223.5.5.5 223.6.6.6'; dns6='2400:3200::1 2400:3200:baba::1'; mirror_host=mirrors.aliyun.com; ntp=time.amazonaws.cn ;;
        --ustc|--china) dns='119.29.29.29'; dns6='2402:4e00::'; mirror_host=mirrors.ustc.edu.cn; ntp=time.amazonaws.cn ;;
        --tuna) dns='119.29.29.29'; dns6='2402:4e00::'; mirror_host=mirrors.tuna.tsinghua.edu.cn; ntp=time.amazonaws.cn ;;
        --interface) interface=$2; shift ;;
        --ip) ip=$2; shift ;;
        --netmask) netmask=$2; shift ;;
        --gateway) gateway=$2; shift ;;
        --dns) dns=$2; shift ;;
        --dns6) dns6=$2; shift ;;
        --hostname) hostname=$2; shift ;;
        --network-console) network_console=true ;;
        --version) set_distro_version "$2"; shift ;;
        --suite) suite=$2; set_daily_d_i; set_security_archive; shift ;;
        --release-d_i) daily_d_i=false ;;
        --daily-d_i) daily_d_i=true ;;
        --mirror-protocol) mirror_protocol=$2; shift ;;
        --https) mirror_protocol=https ;;
        --mirror-host) mirror_host=$2; shift ;;
        --mirror-directory) mirror_directory=${2%/}; shift ;;
        --mirror-proxy|--proxy) mirror_proxy=$2; shift ;;
        --reuse-proxy) set_mirror_proxy ;;
        --security-repository) security_repository=$2; shift ;;
        --no-user|--no-account-setup) account_setup=false ;;
        --user|--username) username=$2; shift ;;
        --password) password=$2; shift ;;
        --authorized-keys-url) authorized_keys_url=$2; shift ;;
        --sudo-with-password) sudo_with_password=true ;;
        --timezone) timezone=$2; shift ;;
        --ntp) ntp=$2; shift ;;
        --no-part|--no-disk-partitioning) disk_partitioning=false ;;
        --force-lowmem) [ "$2" != 0 ] && [ "$2" != 1 ] && [ "$2" != 2 ] && err 'Low memory level can only be 0, 1 or 2'; force_lowmem=$2; shift ;;
        --disk) disk=$2; shift ;;
        --no-force-gpt) force_gpt=false ;;
        --bios) efi=false ;;
        --efi) efi=true ;;
        --esp) esp=$2; shift ;;
        --filesystem) filesystem=$2; shift ;;
        --kernel) kernel=$2; shift ;;
        --cloud-kernel) cloud_kernel=true ;;
        --bpo-kernel) bpo_kernel=true ;;
        --apt-non-free-firmware) apt_non_free_firmware=true ;;
        --apt-non-free) apt_non_free=true; apt_contrib=true ;;
        --apt-contrib) apt_contrib=true ;;
        --apt-src) apt_src=true ;;
        --apt-backports) apt_backports=true ;;
        --no-apt-non-free-firmware) apt_non_free_firmware=false ;;
        --no-apt-non-free) apt_non_free=false ;;
        --no-apt-contrib) apt_contrib=false; apt_non_free=false ;;
        --no-apt-src) apt_src=false ;;
        --no-apt-backports) apt_backports=false ;;
        --no-install-recommends) install_recommends=true ;;
        --install) install=$2; shift ;;
        --no-upgrade) upgrade=none ;;
        --safe-upgrade) upgrade=safe-upgrade ;;
        --full-upgrade) upgrade=full-upgrade ;;
        --ethx) kernel_params="$kernel_params net.ifnames=0 biosdevname=0" ;;
        --bbr) bbr=true ;;
        --ssh-port) ssh_port=$2; shift ;;
        --hold) hold=true ;;
        --power-off) power_off=true ;;
        --architecture) architecture=$2; shift ;;
        --firmware) firmware=true ;;
        --no-force-efi-extra-removable) force_efi_extra_removable=false ;;
        --grub-timeout) grub_timeout=$2; shift ;;
        --dry-run) dry_run=true ;;
        --cidata) cidata=$(realpath "$2"); [ ! -f "$cidata/meta-data" ] && err 'No "meta-data" file found'; [ ! -f "$cidata/user-data" ] && err 'No "user-data" file found'; shift ;;
        *) err "Opção desconhecida: \"$1\"" ;;
    esac
    shift
done

[ -z "$architecture" ] && {
    architecture=$(dpkg --print-architecture 2> /dev/null) || {
        case $(uname -m) in
            x86_64) architecture=amd64 ;;
            aarch64) architecture=arm64 ;;
            i386) architecture=i386 ;;
            *) err 'Arquitetura não especificada' ;;
        esac
    }
}

[ -z "$kernel" ] && {
    if [ "$distro" = "debian" ]; then
        kernel="linux-image-$architecture"
        [ "$cloud_kernel" = true ] && has_cloud_kernel && kernel="linux-image-cloud-$architecture"
        [ "$bpo_kernel" = true ] && has_backports && install="$kernel/$suite-backports $install"
    elif [ "$distro" = "ubuntu" ]; then
        kernel="linux-generic"
    fi
}

[ -n "$authorized_keys_url" ] && ! download "$authorized_keys_url" /dev/null && err "Falha ao baixar chaves SSH de \"$authorized_keys_url\""

if [ "$distro" = "debian" ]; then
    non_free_firmware_available=false
    case $suite in
        bookworm|stable|trixie|testing|sid|unstable) non_free_firmware_available=true ;;
        *) apt_non_free_firmware=false ;;
    esac
    apt_components=main
    [ "$apt_contrib" = true ] && apt_components="$apt_components contrib"
    [ "$apt_non_free" = true ] && apt_components="$apt_components non-free"
    [ "$apt_non_free_firmware" = true ] && apt_components="$apt_components non-free-firmware"
elif [ "$distro" = "ubuntu" ]; then
    apt_components="main restricted universe multiverse"
fi

apt_services=updates
[ "$apt_backports" = true ] && apt_services="$apt_services, backports"

installer_directory="/boot/$distro-$suite"

save_preseed='cat'
[ "$dry_run" = false ] && {
    [ "$(id -u)" -ne 0 ] && err 'Privilégio de root necessário'
    rm -rf "$installer_directory"
    mkdir -p "$installer_directory"
    cd "$installer_directory"
    save_preseed='tee -a preseed.cfg'
}

if [ "$account_setup" = true ]; then
    prompt_password
elif [ "$network_console" = true ] && [ -z "$authorized_keys_url" ]; then
    prompt_password "Escolha uma senha para o console de rede SSH: "
fi

$save_preseed << EOF
# Localização
d-i debian-installer/language string en
d-i debian-installer/country string US
d-i debian-installer/locale string en_US.UTF-8
d-i keyboard-configuration/xkb-keymap select us

# Configuração de rede
d-i netcfg/choose_interface select $interface
EOF

[ -n "$ip" ] && {
    echo 'd-i netcfg/disable_autoconfig boolean true' | $save_preseed
    echo "d-i netcfg/get_ipaddress string $ip" | $save_preseed
    [ -n "$netmask" ] && echo "d-i netcfg/get_netmask string $netmask" | $save_preseed
    [ -n "$gateway" ] && echo "d-i netcfg/get_gateway string $gateway" | $save_preseed
    [ -n "$dns" ] && echo "d-i netcfg/get_nameservers string $dns" | $save_preseed
    [ -n "$dns6" ] && echo "d-i netcfg/get_nameservers string $dns6" | $save_preseed
    echo 'd-i netcfg/confirm_static boolean true' | $save_preseed
}

if [ -n "$hostname" ]; then
    echo "d-i netcfg/hostname string $hostname" | $save_preseed
    hostname=$distro
    domain=
else
    hostname=$(cat /proc/sys/kernel/hostname)
    domain=$(cat /proc/sys/kernel/domainname)
    [ "$domain" = '(none)' ] && domain= || domain=" $domain"
fi

$save_preseed << EOF
d-i netcfg/get_hostname string $hostname
d-i netcfg/get_domain string$domain
EOF

echo 'd-i hw-detect/load_firmware boolean true' | $save_preseed

[ "$network_console" = true ] && {
    $save_preseed << 'EOF'
# Console de rede
d-i anna/choose_modules string network-console
d-i preseed/early_command string anna-install network-console
EOF
    if [ -n "$authorized_keys_url" ]; then
        echo "d-i network-console/authorized_keys_url string $authorized_keys_url" | $save_preseed
    else
        $save_preseed << EOF
d-i network-console/password password $password
d-i network-console/password-again password $password
EOF
    fi
    echo 'd-i network-console/start select Continue' | $save_preseed
}

$save_preseed << EOF
# Configuração do mirror
d-i mirror/country string manual
d-i mirror/protocol string $mirror_protocol
d-i mirror/$mirror_protocol/hostname string $mirror_host
d-i mirror/$mirror_protocol/directory string $mirror_directory
d-i mirror/$mirror_protocol/proxy string $mirror_proxy
d-i mirror/suite string $suite
EOF

[ "$account_setup" = true ] && {
    password_hash=$(mkpasswd -m sha-256 "$password" 2> /dev/null) ||
    password_hash=$(openssl passwd -5 "$password" 2> /dev/null) ||
    password_hash=$(busybox mkpasswd -m sha256 "$password" 2> /dev/null) || {
        for python in python3 python python2; do
            password_hash=$("$python" -c 'import crypt, sys; print(crypt.crypt(sys.argv[1], crypt.mksalt(crypt.METHOD_SHA256)))' "$password" 2> /dev/null) && break
        done
    }
    $save_preseed << 'EOF'
# Configuração de conta
EOF
    [ -n "$authorized_keys_url" ] && configure_sshd PasswordAuthentication no
    if [ "$username" = root ]; then
        if [ -z "$authorized_keys_url" ]; then
            configure_sshd PermitRootLogin yes
        else
            in_target "mkdir -m 0700 -p ~root/.ssh && busybox wget -O- \"$authorized_keys_url\" >> ~root/.ssh/authorized_keys"
        fi
        $save_preseed << 'EOF'
d-i passwd/root-login boolean true
d-i passwd/make-user boolean false
EOF
        if [ -z "$password_hash" ]; then
            $save_preseed << EOF
d-i passwd/root-password password $password
d-i passwd/root-password-again password $password
EOF
        else
            echo "d-i passwd/root-password-crypted password $password_hash" | $save_preseed
        fi
    else
        configure_sshd PermitRootLogin no
        [ -n "$authorized_keys_url" ] &&
        in_target "sudo -u $username mkdir -m 0700 -p ~$username/.ssh && busybox wget -O - \"$authorized_keys_url\" | sudo -u $username tee -a ~$username/.ssh/authorized_keys"
        [ "$sudo_with_password" = false ] &&
        in_target "echo \"$username ALL=(ALL:ALL) NOPASSWD:ALL\" > \"/etc/sudoers.d/90-user-$username\""
        $save_preseed << EOF
d-i passwd/root-login boolean false
d-i passwd/make-user boolean true
d-i passwd/user-fullname string
d-i passwd/username string $username
EOF
        if [ -z "$password_hash" ]; then
            $save_preseed << EOF
d-i passwd/user-password password $password
d-i passwd/user-password-again password $password
EOF
        else
            echo "d-i passwd/user-password-crypted password $password_hash" | $save_preseed
        fi
    fi
}

[ -n "$ssh_port" ] && configure_sshd Port "$ssh_port"

$save_preseed << EOF
# Configuração de horário
d-i time/zone string $timezone
d-i clock-setup/utc boolean true
d-i clock-setup/ntp boolean true
d-i clock-setup/ntp-server string $ntp

# Particionamento
EOF

[ "$disk_partitioning" = true ] && {
    $save_preseed << 'EOF'
d-i partman-auto/method string regular
EOF
    [ -n "$disk" ] && echo "d-i partman-auto/disk string $disk" | $save_preseed || echo 'd-i partman/early_command string debconf-set partman-auto/disk "$(list-devices disk | head -n 1)"' | $save_preseed
}

[ "$force_gpt" = true ] && {
    $save_preseed << 'EOF'
d-i partman-partitioning/choose_label string gpt
d-i partman-partitioning/default_label string gpt
EOF
}

[ "$disk_partitioning" = true ] && {
    echo "d-i partman/default_filesystem string $filesystem" | $save_preseed
    [ -z "$efi" ] && { efi=false; [ -d /sys/firmware/efi ] && efi=true; }
    $save_preseed << 'EOF'
d-i partman-auto/expert_recipe string \
    naive :: \
EOF
    if [ "$efi" = true ]; then
        $save_preseed << EOF
        $esp $esp $esp free \\
EOF
        $save_preseed << 'EOF'
            $iflabel{ gpt } \
            $reusemethod{ } \
            method{ efi } \
            format{ } \
        . \
EOF
    else
        $save_preseed << 'EOF'
        1 1 1 free \
            $iflabel{ gpt } \
            $reusemethod{ } \
            method{ biosgrub } \
        . \
EOF
    fi
    $save_preseed << 'EOF'
        1075 1076 -1 $default_filesystem \
            method{ format } \
            format{ } \
            use_filesystem{ } \
            $default_filesystem{ } \
            mountpoint{ / } \
        .
EOF
    [ "$efi" = true ] && echo 'd-i partman-efi/non_efi_system boolean true' | $save_preseed
    $save_preseed << 'EOF'
d-i partman-auto/choose_recipe select naive
d-i partman-basicfilesystems/no_swap boolean false
d-i partman-partitioning/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i partman-lvm/device_remove_lvm boolean true
EOF
}

$save_preseed << EOF
# Instalação do sistema base
d-i base-installer/kernel/image string $kernel
EOF

[ "$install_recommends" = false ] && echo "d-i base-installer/install-recommends boolean $install_recommends" | $save_preseed

[ "$security_repository" = mirror ] && security_repository=$mirror_protocol://$mirror_host${mirror_directory%/*}/$distro-security

$save_preseed << EOF
# Configuração do APT
d-i apt-setup/contrib boolean $apt_contrib
d-i apt-setup/non-free boolean $apt_non_free
d-i apt-setup/enable-source-repositories boolean $apt_src
d-i apt-setup/services-select multiselect $apt_services
EOF

[ "$distro" = "debian" ] && [ "$non_free_firmware_available" = true ] && echo "d-i apt-setup/non-free-firmware boolean $apt_non_free_firmware" | $save_preseed

[ "$distro" = "debian" ] && [ -n "$security_archive" ] || [ "$distro" = "ubuntu" ] && {
    $save_preseed << EOF
d-i apt-setup/local0/repository string $security_repository $security_archive $apt_components
d-i apt-setup/local0/source boolean $apt_src
EOF
}

$save_preseed << 'EOF'
# Seleção de pacotes
tasksel tasksel/first multiselect ssh-server
EOF

install="$install ca-certificates libpam-systemd wget curl sudo"
[ -n "$cidata" ] && install="$install cloud-init"

[ -n "$install" ] && echo "d-i pkgsel/include string $install" | $save_preseed
[ -n "$upgrade" ] && echo "d-i pkgsel/upgrade select $upgrade" | $save_preseed

$save_preseed << 'EOF'
popularity-contest popularity-contest/participate boolean false

# Instalação do bootloader
EOF

[ -n "$disk" ] && echo "d-i grub-installer/bootdev string $disk" | $save_preseed || echo 'd-i grub-installer/bootdev string default' | $save_preseed
[ "$force_efi_extra_removable" = true ] && echo 'd-i grub-installer/force-efi-extra-removable boolean true' | $save_preseed
[ -n "$kernel_params" ] && echo "d-i debian-installer/add-kernel-opts string$kernel_params" | $save_preseed

$save_preseed << 'EOF'
# Finalização
EOF

[ "$hold" = false ] && echo 'd-i finish-install/reboot_in_progress note' | $save_preseed

[ "$bbr" = true ] && in_target '{ echo "net.core.default_qdisc=fq"; echo "net.ipv4.tcp_congestion_control=bbr"; } > /etc/sysctl.d/bbr.conf'
[ -n "$cidata" ] && in_target 'echo "{ datasource_list: [ NoCloud ], datasource: { NoCloud: { fs_label: ~ } } }" > /etc/cloud/cloud.cfg.d/99_debi.cfg'

late_command='true'
[ -n "$in_target_script" ] && late_command="$late_command; in-target sh -c '$in_target_script'"
[ -n "$cidata" ] && late_command="$late_command; mkdir -p /target/var/lib/cloud/seed/nocloud; cp -r /cidata/. /target/var/lib/cloud/seed/nocloud/"

echo "d-i preseed/late_command string $late_command" | $save_preseed
[ "$power_off" = true ] && echo 'd-i debian-installer/exit/poweroff boolean true' | $save_preseed

save_grub_cfg='cat'
[ "$dry_run" = false ] && {
    base_url="$mirror_protocol://$mirror_host$mirror_directory/dists/$suite/main/installer-$architecture/current/images/netboot/debian-installer/$architecture"
    [ "$distro" = "debian" ] && [ "$suite" = stretch ] && [ "$efi" = true ] && base_url="$mirror_protocol://$mirror_host$mirror_directory/dists/buster/main/installer-$architecture/current/images/netboot/debian-installer/$architecture"
    [ "$distro" = "debian" ] && [ "$daily_d_i" = true ] && base_url="https://d-i.debian.org/daily-images/$architecture/daily/netboot/debian-installer/$architecture"
    firmware_url="https://cdimage.debian.org/cdimage/unofficial/non-free/firmware/$suite/current/firmware.cpio.gz"

    download "$base_url/linux" linux
    download "$base_url/initrd.gz" initrd.gz
    [ "$firmware" = true ] && download "$firmware_url" firmware.cpio.gz

    gzip -d initrd.gz
    echo preseed.cfg | cpio -o -H newc -A -F initrd
    [ -n "$cidata" ] && { cp -r "$cidata" cidata; find cidata | cpio -o -H newc -A -F initrd; }
    gzip -1 initrd

    mkdir -p /etc/default/grub.d
    tee /etc/default/grub.d/zz-debi.cfg 1>&2 << EOF
GRUB_DEFAULT=debi
GRUB_TIMEOUT=$grub_timeout
GRUB_TIMEOUT_STYLE=menu
EOF

    if command_exists update-grub; then
        grub_cfg=/boot/grub/grub.cfg
        update-grub
    elif command_exists grub2-mkconfig; then
        tmp=$(mktemp)
        grep -vF zz_debi /etc/default/grub > "$tmp"
        cat "$tmp" > /etc/default/grub
        rm "$tmp"
        echo 'zz_debi=/etc/default/grub.d/zz-debi.cfg; if [ -f "$zz_debi" ]; then . "$zz_debi"; fi' >> /etc/default/grub
        grub_cfg=/boot/grub2/grub.cfg
        [ -d /sys/firmware/efi ] && grub_cfg=/boot/efi/EFI/*/grub.cfg
        grub2-mkconfig -o "$grub_cfg"
    elif command_exists grub-mkconfig; then
        tmp=$(mktemp)
        grep -vF zz_debi /etc/default/grub > "$tmp"
        cat "$tmp" > /etc/default/grub
        rm "$tmp"
        echo 'zz_debi=/etc/default/grub.d/zz-debi.cfg; if [ -f "$zz_debi" ]; then . "$zz_debi"; fi' >> /etc/default/grub
        grub_cfg=/boot/grub/grub.cfg
        grub-mkconfig -o "$grub_cfg"
    else
        err 'Comando "update-grub", "grub2-mkconfig" ou "grub-mkconfig" não encontrado'
    fi
    save_grub_cfg="tee -a $grub_cfg"
}

mkrelpath=$installer_directory
[ "$dry_run" = true ] && mkrelpath=/boot
installer_directory=$(grub-mkrelpath "$mkrelpath" 2> /dev/null) || installer_directory=$(grub2-mkrelpath "$mkrelpath" 2> /dev/null) || err 'Comando "grub-mkrelpath" ou "grub2-mkrelpath" não encontrado'
[ "$dry_run" = true ] && installer_directory="$installer_directory/$distro-$suite"

kernel_params="$kernel_params lowmem/low=1"
[ -n "$force_lowmem" ] && kernel_params="$kernel_params lowmem=+$force_lowmem"

initrd="$installer_directory/initrd.gz"
[ "$firmware" = true ] && initrd="$initrd $installer_directory/firmware.cpio.gz"

$save_grub_cfg 1>&2 << EOF
menuentry '$distro Installer' --id debi {
    insmod part_msdos
    insmod part_gpt
    insmod ext2
    insmod xfs
    insmod btrfs
    linux $installer_directory/linux$kernel_params
    initrd $initrd
}
EOF

clear
echo -e "\033[1;31m═══════════════════════════════════════\033[0m"
tput setaf 8 ; tput setab 4 ; tput bold ; printf '%25s%s%-14s\n' "FINALIZADO!" ; tput sgr0
echo -e "\033[1;31m═══════════════════════════════════════\033[0m"
echo -e "\033[33mO servidor será reiniciado.\nPor favor, aguarde alguns minutos antes\nde tentar se reconectar ao SSH.\nAgradecemos sua compreensão e paciência.\033[0m"
echo -ne "\033[31mEnter para continuar ou CTRL+C para cancelar: \033[0m"; read -r enter

[ "$(whoami)" != "root" ] && sudo reboot || reboot
