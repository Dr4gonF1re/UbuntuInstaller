#!/bin/bash

set -eu

# Funções auxiliares
err() {
    printf "\nErro: %s.\n" "$1" 1>&2
    exit 1
}

warn() {
    printf "\nAviso: %s.\nContinuando com o padrão...\n" "$1" 1>&2
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
    in_target sed -Ei "\"s/^#?$1 .+/$1 $2/"\" /etc/ssh/sshd_config
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

set_suite() {
    suite=$1
}

set_ubuntu_version() {
    case $1 in
        18|bionic) set_suite bionic ;;
        20|focal) set_suite focal ;;
        22|jammy) set_suite jammy ;;
        24|noble) set_suite noble ;;
        *) err "Versão não suportada: $1" ;;
    esac
}

# Seleção da versão do Ubuntu
ubuntu_version=20
while true; do
    clear
    echo -e "\033[1;31m═══════════════════════════════════════════════\033[0m"
    tput setaf 8 ; tput setab 4 ; tput bold ; printf '%36s%s%-12s\n' "ESCOLHA A VERSÃO DO UBUNTU" ; tput sgr0
    echo -e "\033[1;31m═══════════════════════════════════════════════\033[0m"
    echo -e "\033[1;32mRecomenda-se a versão 20 do Ubuntu.\033[0m"
    echo -ne "Escolha (18, 20, 22, 24) [Padrão: 20]: "
    read -r user_input
    ubuntu_version=${user_input:-$ubuntu_version}
    if [[ "$ubuntu_version" =~ ^(18|20|22|24|bionic|focal|jammy|noble)$ ]]; then
        break
    else
        err "Versão não suportada: $ubuntu_version"
    fi
done

# Variáveis padrão
interface=auto
ip=
netmask=
gateway=
dns='1.1.1.1 8.8.8.8'
dns6='2606:4700:4700::1111 2001:4860:4860::8888'
hostname=
network_console=false
set_ubuntu_version "$ubuntu_version"
mirror_protocol=http
mirror_host=archive.ubuntu.com
mirror_directory=/ubuntu
mirror_proxy=
security_repository=http://security.ubuntu.com/ubuntu
account_setup=true
username=root
password=
authorized_keys_url=
sudo_with_password=false
timezone=UTC-3
ntp=ntp.ubuntu.com
disk_partitioning=true
disk="/dev/sda"
force_gpt=true
efi=
esp=106
filesystem=ext4
kernel=linux-generic
install_recommends=true
install=
upgrade=
kernel_params=
force_lowmem=
ssh_port=
hold=false
power_off=false
architecture=
firmware=false
force_efi_extra_removable=true
grub_timeout=5
dry_run=false
apt_universe=false
apt_multiverse=false
cidata=

# Processamento das opções de linha de comando
while [ $# -gt 0 ]; do
    case $1 in
        --interface) interface=$2; shift ;;
        --ip) ip=$2; shift ;;
        --netmask) netmask=$2; shift ;;
        --gateway) gateway=$2; shift ;;
        --dns) dns=$2; shift ;;
        --dns6) dns6=$2; shift ;;
        --hostname) hostname=$2; shift ;;
        --network-console) network_console=true ;;
        --version) set_ubuntu_version "$2"; shift ;;
        --mirror-protocol) mirror_protocol=$2; shift ;;
        --mirror-host) mirror_host=$2; shift ;;
        --mirror-directory) mirror_directory=${2%/}; shift ;;
        --mirror-proxy|--proxy) mirror_proxy=$2; shift ;;
        --reuse-proxy) set_mirror_proxy ;;
        --no-user|--no-account-setup) account_setup=false ;;
        --user|--username) username=$2; shift ;;
        --password) password=$2; shift ;;
        --authorized-keys-url) authorized_keys_url=$2; shift ;;
        --sudo-with-password) sudo_with_password=true ;;
        --timezone) timezone=$2; shift ;;
        --ntp) ntp=$2; shift ;;
        --no-part|--no-disk-partitioning) disk_partitioning=false ;;
        --force-lowmem) [ "$2" != 0 ] && [ "$2" != 1 ] && [ "$2" != 2 ] && err 'Nível de memória baixa só pode ser 0, 1 ou 2'; force_lowmem=$2; shift ;;
        --disk) disk=$2; shift ;;
        --no-force-gpt) force_gpt=false ;;
        --bios) efi=false ;;
        --efi) efi=true ;;
        --esp) esp=$2; shift ;;
        --filesystem) filesystem=$2; shift ;;
        --kernel) kernel=$2; shift ;;
        --no-install-recommends) install_recommends=false ;;
        --install) install=$2; shift ;;
        --no-upgrade) upgrade=none ;;
        --safe-upgrade) upgrade=safe-upgrade ;;
        --full-upgrade) upgrade=full-upgrade ;;
        --ssh-port) ssh_port=$2; shift ;;
        --hold) hold=true ;;
        --power-off) power_off=true ;;
        --architecture) architecture=$2; shift ;;
        --firmware) firmware=true ;;
        --no-force-efi-extra-removable) force_efi_extra_removable=false ;;
        --grub-timeout) grub_timeout=$2; shift ;;
        --dry-run) dry_run=true ;;
        --cidata) cidata=$(realpath "$2"); [ ! -f "$cidata/meta-data" ] && err 'Arquivo "meta-data" não encontrado'; [ ! -f "$cidata/user-data" ] && err 'Arquivo "user-data" não encontrado'; shift ;;
        --apt-universe) apt_universe=true ;;
        --apt-multiverse) apt_multiverse=true ;;
        *) err "Opção desconhecida: \"$1\"" ;;
    esac
    shift
done

# Determinar arquitetura se não especificada
[ -z "$architecture" ] && {
    architecture=$(dpkg --print-architecture 2> /dev/null) || {
        case $(uname -m) in
            x86_64) architecture=amd64 ;;
            aarch64) architecture=arm64 ;;
            i386) architecture=i386 ;;
            *) err 'Nenhuma "--architecture" especificada' ;;
        esac
    }
}

[ -n "$authorized_keys_url" ] && ! download "$authorized_keys_url" /dev/null && err "Falha ao baixar chaves SSH de \"$authorized_keys_url\""

# Configuração dos componentes APT
apt_components="main restricted"
[ "$apt_universe" = true ] && apt_components="$apt_components universe"
[ "$apt_multiverse" = true ] && apt_components="$apt_components multiverse"

installer_directory="/boot/ubuntu-$suite"

# Preparação para execução real ou simulação
save_preseed='cat'
[ "$dry_run" = false ] && {
    [ "$(id -u)" -ne 0 ] && err 'Privilégio de root é necessário'
    rm -rf "$installer_directory"
    mkdir -p "$installer_directory"
    cd "$installer_directory"
    save_preseed='tee -a preseed.cfg'
}

# Solicitar senha se necessário
[ "$account_setup" = true ] && prompt_password
[ "$network_console" = true ] && [ -z "$authorized_keys_url" ] && prompt_password "Escolha uma senha para o console de rede SSH: "

# Geração do arquivo preseed
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

[ -n "$hostname" ] && { echo "d-i netcfg/hostname string $hostname" | $save_preseed; hostname=ubuntu; domain=; } || {
    hostname=$(cat /proc/sys/kernel/hostname)
    domain=$(cat /proc/sys/kernel/domainname)
    [ "$domain" = '(none)' ] && domain= || domain=" $domain"
}

$save_preseed << EOF
d-i netcfg/get_hostname string $hostname
d-i netcfg/get_domain string$domain
d-i hw-detect/load_firmware boolean true
EOF

[ "$network_console" = true ] && {
    $save_preseed << 'EOF'
# Console de rede
d-i anna/choose_modules string network-console
d-i preseed/early_command string anna-install network-console
EOF
    [ -n "$authorized_keys_url" ] && echo "d-i network-console/authorized_keys_url string $authorized_keys_url" | $save_preseed || $save_preseed << EOF
d-i network-console/password password $password
d-i network-console/password-again password $password
EOF
    echo 'd-i network-console/start select Continue' | $save_preseed
}

$save_preseed << EOF
# Configuração do espelho
d-i mirror/country string manual
d-i mirror/protocol string $mirror_protocol
d-i mirror/$mirror_protocol/hostname string $mirror_host
d-i mirror/$mirror_protocol/directory string $mirror_directory
d-i mirror/$mirror_protocol/proxy string $mirror_proxy
d-i mirror/suite string $suite
EOF

[ "$account_setup" = true ] && {
    password_hash=$(mkpasswd -m sha-256 "$password" 2> /dev/null || openssl passwd -5 "$password" 2> /dev/null || busybox mkpasswd -m sha256 "$password" 2> /dev/null || for python in python3 python python2; do "$python" -c 'import crypt, sys; print(crypt.crypt(sys.argv[1], crypt.mksalt(crypt.METHOD_SHA256)))' "$password" 2> /dev/null && break; done)
    $save_preseed << 'EOF'
# Configuração de conta
EOF
    [ -n "$authorized_keys_url" ] && configure_sshd PasswordAuthentication no
    if [ "$username" = root ]; then
        [ -z "$authorized_keys_url" ] && configure_sshd PermitRootLogin yes || in_target "mkdir -m 0700 -p ~root/.ssh && busybox wget -O- \"$authorized_keys_url\" >> ~root/.ssh/authorized_keys"
        $save_preseed << 'EOF'
d-i passwd/root-login boolean true
d-i passwd/make-user boolean false
EOF
        [ -z "$password_hash" ] && $save_preseed << EOF
d-i passwd/root-password password $password
d-i passwd/root-password-again password $password
EOF || echo "d-i passwd/root-password-crypted password $password_hash" | $save_preseed
    else
        configure_sshd PermitRootLogin no
        [ -n "$authorized_keys_url" ] && in_target "sudo -u $username mkdir -m 0700 -p ~$username/.ssh && busybox wget -O - \"$authorized_keys_url\" | sudo -u $username tee -a ~$username/.ssh/authorized_keys"
        [ "$sudo_with_password" = false ] && in_target "echo \"$username ALL=(ALL:ALL) NOPASSWD:ALL\" > \"/etc/sudoers.d/90-user-$username\""
        $save_preseed << EOF
d-i passwd/root-login boolean false
d-i passwd/make-user boolean true
d-i passwd/user-fullname string
d-i passwd/username string $username
EOF
        [ -z "$password_hash" ] && $save_preseed << EOF
d-i passwd/user-password password $password
d-i passwd/user-password-again password $password
EOF || echo "d-i passwd/user-password-crypted password $password_hash" | $save_preseed
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

[ "$force_gpt" = true ] && $save_preseed << 'EOF'
d-i partman-partitioning/choose_label string gpt
d-i partman-partitioning/default_label string gpt
EOF

[ "$disk_partitioning" = true ] && {
    echo "d-i partman/default_filesystem string $filesystem" | $save_preseed
    [ -z "$efi" ] && { efi=false; [ -d /sys/firmware/efi ] && efi=true; }
    if [ "$efi" = true ]; then
        conditional_recipe="
            $esp $esp $esp free \\
                \$iflabel{ gpt } \\
                \$reusemethod{ } \\
                method{ efi } \\
                format{ } \\
            . \\
        "
    else
        conditional_recipe="
            1 1 1 free \\
                \$iflabel{ gpt } \\
                \$reusemethod{ } \\
                method{ biosgrub } \\
            . \\
        "
    fi
    $save_preseed << EOF
d-i partman-auto/expert_recipe string \\
    naive :: \\
        $conditional_recipe \\
        1075 1076 -1 $filesystem \\
            method{ format } \\
            format{ } \\
            use_filesystem{ } \\
            $filesystem{ } \\
            mountpoint{ / } \\
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

$save_preseed << EOF
# Configuração do APT
d-i apt-setup/restricted boolean true
d-i apt-setup/universe boolean $apt_universe
d-i apt-setup/multiverse boolean $apt_multiverse
d-i apt-setup/services-select multiselect updates, security

# Seleção de pacotes
tasksel tasksel/first multiselect standard, ubuntu-server
EOF

install="$install ca-certificates libpam-systemd wget curl sudo"
[ -n "$cidata" ] && install="$install cloud-init"
[ -n "$install" ] && echo "d-i pkgsel/include string $install" | $save_preseed
[ -n "$upgrade" ] && echo "d-i pkgsel/upgrade select $upgrade" | $save_preseed

$save_preseed << 'EOF'
popularity-contest popularity-contest/participate boolean false

# Instalação do carregador de inicialização
EOF

[ -n "$disk" ] && echo "d-i grub-installer/bootdev string $disk" | $save_preseed || echo 'd-i grub-installer/bootdev string default' | $save_preseed
[ "$force_efi_extra_removable" = true ] && echo 'd-i grub-installer/force-efi-extra-removable boolean true' | $save_preseed
[ -n "$kernel_params" ] && echo "d-i debian-installer/add-kernel-opts string$kernel_params" | $save_preseed

$save_preseed << 'EOF'
# Finalização da instalação
EOF

[ "$hold" = false ] && echo 'd-i finish-install/reboot_in_progress note' | $save_preseed

late_command='true'
[ -n "$in_target_script" ] && late_command="$late_command; in-target sh -c '$in_target_script'"
[ -n "$cidata" ] && late_command="$late_command; mkdir -p /target/var/lib/cloud/seed/nocloud; cp -r /cidata/. /target/var/lib/cloud/seed/nocloud/"
echo "d-i preseed/late_command string $late_command" | $save_preseed

[ "$power_off" = true ] && echo 'd-i debian-installer/exit/poweroff boolean true' | $save_preseed

# Configuração do GRUB e download dos arquivos do instalador
save_grub_cfg='cat'
[ "$dry_run" = false ] && {
    case $suite in
        bionic) installer_url="http://archive.ubuntu.com/ubuntu/dists/bionic/main/installer-$architecture/current/images/netboot/ubuntu-installer/$architecture" ;;
        focal) installer_url="http://archive.ubuntu.com/ubuntu/dists/focal/main/installer-$architecture/current/legacy-images/netboot/ubuntu-installer/$architecture" ;;
        jammy) installer_url="http://archive.ubuntu.com/ubuntu/dists/jammy/main/installer-$architecture/current/legacy-images/netboot/ubuntu-installer/$architecture" ;;
        noble) installer_url="http://archive.ubuntu.com/ubuntu/dists/noble/main/installer-$architecture/current/legacy-images/netboot/ubuntu-installer/$architecture" ;;
    esac

    download "$installer_url/linux" linux
    download "$installer_url/initrd.gz" initrd.gz

    gzip -d initrd.gz
    echo preseed.cfg | cpio -o -H newc -A -F initrd
    [ -n "$cidata" ] && { cp -r "$cidata" cidata; find cidata | cpio -o -H newc -A -F initrd; }
    gzip -1 initrd

    mkdir -p /etc/default/grub.d
    tee /etc/default/grub.d/zz-ubuntu.cfg 1>&2 << EOF
GRUB_DEFAULT=ubuntu
GRUB_TIMEOUT=$grub_timeout
GRUB_TIMEOUT_STYLE=menu
EOF

    if command_exists update-grub; then
        grub_cfg=/boot/grub/grub.cfg
        update-grub
    elif command_exists grub2-mkconfig; then
        tmp=$(mktemp); grep -vF zz_ubuntu /etc/default/grub > "$tmp"; cat "$tmp" > /etc/default/grub; rm "$tmp"
        echo 'zz_ubuntu=/etc/default/grub.d/zz-ubuntu.cfg; if [ -f "$zz_ubuntu" ]; then . "$zz_ubuntu"; fi' >> /etc/default/grub
        grub_cfg=/boot/grub2/grub.cfg; [ -d /sys/firmware/efi ] && grub_cfg=/boot/efi/EFI/*/grub.cfg
        grub2-mkconfig -o "$grub_cfg"
    elif command_exists grub-mkconfig; then
        tmp=$(mktemp); grep -vF zz_ubuntu /etc/default/grub > "$tmp"; cat "$tmp" > /etc/default/grub; rm "$tmp"
        echo 'zz_ubuntu=/etc/default/grub.d/zz-ubuntu.cfg; if [ -f "$zz_ubuntu" ]; then . "$zz_ubuntu"; fi' >> /etc/default/grub
        grub_cfg=/boot/grub/grub.cfg
        grub-mkconfig -o "$grub_cfg"
    else
        err 'Não encontrou "update-grub", "grub2-mkconfig" ou "grub-mkconfig"'
    fi
    save_grub_cfg="tee -a $grub_cfg"
}

mkrelpath=$installer_directory
[ "$dry_run" = true ] && mkrelpath=/boot
installer_directory=$(grub-mkrelpath "$mkrelpath" 2> /dev/null || grub2-mkrelpath "$mkrelpath" 2> /dev/null) || err 'Não encontrou "grub-mkrelpath" ou "grub2-mkrelpath"'
[ "$dry_run" = true ] && installer_directory="$installer_directory/ubuntu-$suite"

kernel_params="$kernel_params lowmem/low=1"
[ -n "$force_lowmem" ] && kernel_params="$kernel_params lowmem=+$force_lowmem"
initrd="$installer_directory/initrd.gz"

$save_grub_cfg 1>&2 << EOF
menuentry 'Ubuntu Installer' --id ubuntu {
    insmod part_msdos
    insmod part_gpt
    insmod ext2
    insmod xfs
    insmod btrfs
    linux $installer_directory/linux$kernel_params
    initrd $initrd
}
EOF

# Mensagem final e reinicialização
clear
echo -e "\033[1;31m═══════════════════════════════════════\033[0m"
tput setaf 8 ; tput setab 4 ; tput bold ; printf '%25s%s%-14s\n' "FINALIZADO!" ; tput sgr0
echo -e "\033[1;31m═══════════════════════════════════════\033[0m"
echo -e "\033[33mO servidor será reiniciado.\033[0m"
echo -e "\033[33mAguarde alguns minutos antes de reconectar ao SSH.\033[0m"
echo -e "\033[33mAgradecemos sua paciência.\033[0m"
echo -ne "\033[31mEnter para continuar ou CTRL+C para cancelar: \033[0m"; read -r enter

[ "$(whoami)" != "root" ] && sudo reboot || reboot
