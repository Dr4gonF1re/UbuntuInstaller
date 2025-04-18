#!/bin/bash

# Ativa opções para parar o script em caso de erro ou variável não definida
set -eu

# Funções auxiliares
# ------------------------------------------------------------------------------

# Exibe uma mensagem de erro e sai com código de erro 1
err() {
    printf "\n\033[1;31mErro: %s.\033[0m\n" "$*" >&2
    exit 1
}

# Exibe uma mensagem de aviso e continua a execução
warn() {
    printf "\n\033[1;33mAviso: %s.\nContinuando com o padrão...\033[0m\n" "$*" >&2
    sleep 5
}

# Verifica se um comando existe no sistema
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Executa comandos no ambiente de instalação (usado em preseed/late_command)
in_target_script=
in_target() {
    local command=
    for argument in "$@"; do
        command="$command $argument"
    done
    [ -n "$command" ] && {
        [ -z "$in_target_script" ] && in_target_script='true'
        in_target_script="$in_target_script;$command"
    }
}

# Faz backup de arquivos no ambiente de instalação
in_target_backup() {
    in_target "if [ ! -e \"$1.backup\" ]; then cp \"$1\" \"$1.backup\"; fi"
}

# Configura o SSH no ambiente de instalação
configure_sshd() {
    [ -z "${sshd_config_backup+1s}" ] && in_target_backup /etc/ssh/sshd_config
    sshd_config_backup=
    in_target sed -Ei \""s/^#?$1 .+/$1 $2/"\" /etc/ssh/sshd_config
}

# Solicita senha com validação
prompt_password() {
    local prompt="Senha do usuário ${username:-root}: "
    while true; do
        echo -e "\n\033[1;31m═══════════════════════════════════════════════\033[0m"
        tput setaf 8 ; tput setab 4 ; tput bold ; printf '%33s%s%-14s\n' "DEFINIR A SENHA" ; tput sgr0
        echo -e "\033[1;31m═══════════════════════════════════════════════\033[0m"
        echo -ne "\n\033[1;33m$prompt\033[0m"
        read -r password
        if [ -z "$password" ]; then
            echo -e "\n\033[1;31mSenha não pode estar vazia.\033[0m"
        elif [ "${#password}" -lt 8 ]; then
            echo -e "\n\033[1;31mSenha deve ter pelo menos 8 caracteres.\033[0m"
        else
            break
        fi
    done
}

# Baixa arquivos usando wget, curl ou busybox
download() {
    local url="$1" output="$2"
    set_mirror_proxy
    [ -n "$mirror_proxy" ] && [ -z "${http_proxy+1s}" ] && [ -z "${https_proxy+1s}" ] && [ -z "${ftp_proxy+1s}" ] && {
        export http_proxy="$mirror_proxy"
        export https_proxy="$mirror_proxy"
        export ftp_proxy="$mirror_proxy"
    }
    if command_exists wget; then
        wget -q "$url" -O "$output" || err "Falha ao baixar $url com wget"
    elif command_exists curl; then
        curl -s -L "$url" -o "$output" || err "Falha ao baixar $url com curl"
    elif command_exists busybox && busybox wget --help >/dev/null 2>&1; then
        busybox wget -q "$url" -O "$output" || err "Falha ao baixar $url com busybox"
    else
        err "Nenhum utilitário de download encontrado (wget, curl ou busybox)"
    fi
}

# Configura proxy para espelhos
set_mirror_proxy() {
    [ -n "$mirror_proxy" ] && return
    case $mirror_protocol in
        http) [ -n "${http_proxy+1s}" ] && mirror_proxy="$http_proxy" ;;
        https) [ -n "${https_proxy+1s}" ] && mirror_proxy="$https_proxy" ;;
        ftp) [ -n "${ftp_proxy+1s}" ] && mirror_proxy="$ftp_proxy" ;;
        *) err "Protocolo não suportado: $mirror_protocol" ;;
    esac
}

# Limpa arquivos temporários
cleanup() {
    echo "Limpando arquivos temporários..."
    [ -d "$WORKDIR" ] && rm -rf "$WORKDIR" || warn "Falha ao limpar $WORKDIR"
    [ -d "$boot_dir" ] && rm -rf "$boot_dir" || warn "Falha ao limpar $boot_dir"
}

# Variáveis padrão
# ------------------------------------------------------------------------------

WORKDIR="/tmp/ubuntu-install"
interface="auto"
ip=""
netmask=""
gateway=""
nameserver="8.8.8.8"
hostname=""
domain=""
version="22.04"
architecture=""
firmware=false
dry_run=false
boot_dir="/boot/ubuntu-install"
mirror_protocol="http"
mirror_host="archive.ubuntu.com"
mirror_directory="/ubuntu"
mirror_proxy=""
username="root"
password=""
authorized_keys_url=""
sudo_with_password=false
timezone="UTC"
ntp="pool.ntp.org"
disk_partitioning=true
disk=""
force_gpt=true
efi=""
esp=106
filesystem="ext4"
kernel="linux-generic"
cloud_kernel=false
install_recommends=true
install="openssh-server ca-certificates wget curl sudo"
upgrade="none"
kernel_params=""
force_lowmem=""
ssh_port=""
power_off=false
force_efi_extra_removable=true
grub_timeout=5
apt_restricted=true
apt_universe=true
apt_multiverse=false
apt_backports=false
cidata=""
network_console=false

# Mapeia versões do Ubuntu para codinomes
set_ubuntu_version() {
    case "$version" in
        14.04) codename="trusty" ;;
        16.04) codename="xenial" ;;
        18.04) codename="bionic" ;;
        20.04) codename="focal" ;;
        22.04) codename="jammy" ;;
        24.04) codename="noble" ;;
        *) err "Versão do Ubuntu não suportada: $version" ;;
    esac
}

# Solicita versão do Ubuntu
prompt_version() {
    local user_input
    while true; do
        clear
        echo -e "\033[1;31m═══════════════════════════════════════════════\033[0m"
        tput setaf 8 ; tput setab 4 ; tput bold ; printf '%36s%s%-12s\n' "ESCOLHA A VERSÃO DO UBUNTU" ; tput sgr0
        echo -e "\033[1;31m═══════════════════════════════════════════════\033[0m"
        echo -e "\n\033[1;32mRecomenda-se a versão 22.04 do Ubuntu.\033[0m"
        echo -ne "\nEscolha (14.04, 16.04, 18.04, 20.04, 22.04, 24.04) [Padrão: 22.04]: "
        read -r user_input
        version=${user_input:-$version}
        if [[ "$version" =~ ^(14.04|16.04|18.04|20.04|22.04|24.04)$ ]]; then
            set_ubuntu_version
            break
        else
            err "Versão não suportada: $version"
        fi
    done
}

# Parseamento de argumentos da linha de comando
# ------------------------------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        --interface) interface="$2"; shift 2 ;;
        --ip) ip="$2"; shift 2 ;;
        --netmask) netmask="$2"; shift 2 ;;
        --gateway) gateway="$2"; shift 2 ;;
        --nameserver) nameserver="$2"; shift 2 ;;
        --hostname) hostname="$2"; shift 2 ;;
        --domain) domain="$2"; shift 2 ;;
        --version) version="$2"; set_ubuntu_version; shift 2 ;;
        --architecture) architecture="$2"; shift 2 ;;
        --firmware) firmware=true; shift ;;
        --dry-run) dry_run=true; shift ;;
        --mirror-protocol) mirror_protocol="$2"; shift 2 ;;
        --mirror-host) mirror_host="$2"; shift 2 ;;
        --mirror-directory) mirror_directory="${2%/}"; shift 2 ;;
        --mirror-proxy) mirror_proxy="$2"; shift 2 ;;
        --user|--username) username="$2"; shift 2 ;;
        --password) password="$2"; shift 2 ;;
        --authorized-keys-url) authorized_keys_url="$2"; shift 2 ;;
        --sudo-with-password) sudo_with_password=true; shift ;;
        --timezone) timezone="$2"; shift 2 ;;
        --ntp) ntp="$2"; shift 2 ;;
        --no-disk-partitioning) disk_partitioning=false; shift ;;
        --disk) disk="$2"; shift 2 ;;
        --no-force-gpt) force_gpt=false; shift ;;
        --bios) efi=false; shift ;;
        --efi) efi=true; shift ;;
        --esp) esp="$2"; shift 2 ;;
        --filesystem) filesystem="$2"; shift 2 ;;
        --kernel) kernel="$2"; shift 2 ;;
        --cloud-kernel) cloud_kernel=true; shift ;;
        --no-install-recommends) install_recommends=false; shift ;;
        --install) install="$2"; shift 2 ;;
        --no-upgrade) upgrade="none"; shift ;;
        --safe-upgrade) upgrade="safe-upgrade"; shift ;;
        --full-upgrade) upgrade="full-upgrade"; shift ;;
        --force-lowmem) [[ "$2" =~ ^(0|1|2)$ ]] || err "Nível de memória baixa deve ser 0, 1 ou 2"; force_lowmem="$2"; shift 2 ;;
        --ssh-port) ssh_port="$2"; shift 2 ;;
        --power-off) power_off=true; shift ;;
        --no-force-efi-extra-removable) force_efi_extra_removable=false; shift ;;
        --grub-timeout) grub_timeout="$2"; shift 2 ;;
        --apt-restricted) apt_restricted=true; shift ;;
        --apt-universe) apt_universe=true; shift ;;
        --apt-multiverse) apt_multiverse=true; shift ;;
        --apt-backports) apt_backports=true; shift ;;
        --no-apt-restricted) apt_restricted=false; shift ;;
        --no-apt-universe) apt_universe=false; shift ;;
        --no-apt-multiverse) apt_multiverse=false; shift ;;
        --no-apt-backports) apt_backports=false; shift ;;
        --cidata) cidata=$(realpath "$2"); [ ! -f "$cidata/meta-data" ] || [ ! -f "$cidata/user-data" ] && err "Arquivos meta-data ou user-data ausentes em $cidata"; shift 2 ;;
        --network-console) network_console=true; shift ;;
        *) err "Opção desconhecida: $1" ;;
    esac
done

# Determina a arquitetura do sistema se não especificada
# ------------------------------------------------------------------------------

if [ -z "$architecture" ]; then
    if command_exists dpkg; then
        architecture=$(dpkg --print-architecture)
    else
        case $(uname -m) in
            x86_64) architecture="amd64" ;;
            aarch64) architecture="arm64" ;;
            *) err "Arquitetura não suportada: $(uname -m)" ;;
        esac
    fi
fi

# Mapeia aarch64 para arm64
case "$architecture" in
    aarch64) architecture="arm64" ;;
    amd64|arm64) ;;
    *) err "Arquitetura não suportada: $architecture" ;;
esac

# Configura kernel para cloud se necessário
[ -z "$kernel" ] && {
    kernel="linux-generic"
    [ "$cloud_kernel" = true ] && kernel="linux-cloud"
}

# Solicita versão e senha se necessário
[ -z "$password" ] && [ "$network_console" = true ] && prompt_password "Escolha uma senha para o console de rede SSH: "
[ -z "$password" ] && prompt_password
prompt_version

# Cria o diretório de trabalho
# ------------------------------------------------------------------------------

[ "$dry_run" = false ] && {
    [ "$(id -u)" -ne 0 ] && err "Privilégios de root são necessários"
    mkdir -p "$WORKDIR" || err "Não foi possível criar $WORKDIR"
    cd "$WORKDIR" || err "Não foi possível acessar $WORKDIR"
} || echo "[DRY-RUN] mkdir -p $WORKDIR && cd $WORKDIR"

# Gera o arquivo preseed.cfg
# ------------------------------------------------------------------------------

save_preseed='cat'
[ "$dry_run" = false ] && save_preseed='tee -a preseed.cfg'

$save_preseed << EOF
# Configuração de idioma e local
d-i debian-installer/language string en
d-i debian-installer/country string US
d-i debian-installer/locale string en_US.UTF-8
d-i console-setup/ask_detect boolean false
d-i keyboard-configuration/xkb-keymap select us

# Configuração de rede
d-i netcfg/choose_interface select $interface
EOF

[ -n "$ip" ] && {
    $save_preseed << EOF
d-i netcfg/disable_autoconfig boolean true
d-i netcfg/get_ipaddress string $ip
d-i netmask/get_netmask string $netmask
d-i netcfg/get_gateway string $gateway
d-i netcfg/get_nameservers string $nameserver
d-i netcfg/confirm_static boolean true
EOF
}

[ -n "$hostname" ] || {
    hostname=$(cat /proc/sys/kernel/hostname)
    domain=$(cat /proc/sys/kernel/domainname)
    [ "$domain" = '(none)' ] && domain=""
}

$save_preseed << EOF
d-i netcfg/get_hostname string $hostname
d-i netcfg/get_domain string $domain
d-i hw-detect/load_firmware boolean true
EOF

[ "$network_console" = true ] && {
    $save_preseed << EOF
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
d-i network-console/start select Continue
EOF
    fi
}

$save_preseed << EOF
# Configuração de espelho
d-i mirror/country string manual
d-i mirror/protocol string $mirror_protocol
d-i mirror/$mirror_protocol/hostname string $mirror_host
d-i mirror/$mirror_protocol/directory string $mirror_directory
d-i mirror/$mirror_protocol/proxy string $mirror_proxy
d-i mirror/suite string $codename
EOF

# Configuração de usuário
password_hash=$(mkpasswd -m sha-256 "$password" 2>/dev/null || openssl passwd -5 "$password" 2>/dev/null || busybox mkpasswd -m sha256 "$password" 2>/dev/null || python3 -c 'import crypt, sys; print(crypt.crypt(sys.argv[1], crypt.mksalt(crypt.METHOD_SHA256)))' "$password" 2>/dev/null) || warn "Não foi possível gerar hash da senha, usando texto simples"

$save_preseed << EOF
# Configuração de usuário
EOF

[ -n "$authorized_keys_url" ] && configure_sshd PasswordAuthentication no

if [ "$username" = "root" ]; then
    if [ -z "$authorized_keys_url" ]; then
        configure_sshd PermitRootLogin yes
    else
        in_target "mkdir -m 0700 -p ~root/.ssh && busybox wget -O- \"$authorized_keys_url\" >> ~root/.ssh/authorized_keys"
    fi
    $save_preseed << EOF
d-i passwd/root-login boolean true
d-i passwd/make-user boolean false
EOF
    [ -z "$password_hash" ] && $save_preseed << EOF
d-i passwd/root-password password $password
d-i passwd/root-password-again password $password
EOF
    [ -n "$password_hash" ] && echo "d-i passwd/root-password-crypted password $password_hash" | $save_preseed
else
    configure_sshd PermitRootLogin no
    [ -n "$authorized_keys_url" ] && in_target "sudo -u $username mkdir -m 0700 -p ~$username/.ssh && busybox wget -O- \"$authorized_keys_url\" | sudo -u $username tee -a ~$username/.ssh/authorized_keys"
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
EOF
    [ -n "$password_hash" ] && echo "d-i passwd/user-password-crypted password $password_hash" | $save_preseed
fi

[ -n "$ssh_port" ] && configure_sshd Port "$ssh_port"

$save_preseed << EOF
# Configuração de relógio e fuso horário
d-i clock-setup/utc boolean true
d-i time/zone string $timezone
d-i clock-setup/ntp boolean true
d-i clock-setup/ntp-server string $ntp

# Configuração de disco
EOF

[ "$disk_partitioning" = true ] && {
    $save_preseed << EOF
d-i partman-auto/method string regular
EOF
    [ -n "$disk" ] || disk="/dev/$(lsblk -no PKNAME "$(df /boot | grep -Eo '/dev/[a-z0-9]+')")" || disk=""
    [ -n "$disk" ] && echo "d-i partman-auto/disk string $disk" | $save_preseed || echo 'd-i partman/early_command string debconf-set partman-auto/disk "$(list-devices disk | head -n 1)"' | $save_preseed
}

[ "$force_gpt" = true ] && $save_preseed << EOF
d-i partman-partitioning/choose_label string gpt
d-i partman-partitioning/default_label string gpt
EOF

[ "$disk_partitioning" = true ] && {
    [ -z "$efi" ] && { [ -d /sys/firmware/efi ] && efi=true || efi=false; }
    echo "d-i partman/default_filesystem string $filesystem" | $save_preseed
    $save_preseed << EOF
d-i partman-auto/expert_recipe string \\
    naive :: \\
EOF
    if [ "$efi" = true ]; then
        $save_preseed << EOF
        $esp $esp $esp free \\
            \$iflabel{ gpt } \\
            \$reusemethod{ } \\
            method{ efi } \\
            format{ } \\
        . \\
EOF
    else
        $save_preseed << EOF
        1 1 1 free \\
            \$iflabel{ gpt } \\
            \$reusemethod{ } \\
            method{ biosgrub } \\
        . \\
EOF
    fi
    $save_preseed << EOF
        1075 1076 -1 $filesystem \\
            method{ format } \\
            format{ } \\
            use_filesystem{ } \\
            $filesystem{ } \\
            mountpoint{ / } \\
        . \\
d-i partman-auto/choose_recipe select naive
d-i partman-basicfilesystems/no_swap boolean false
d-i partman-partitioning/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i partman-lvm/device_remove_lvm boolean true
EOF
    [ "$efi" = true ] && echo 'd-i partman-efi/non_efi_system boolean true' | $save_preseed
}

$save_preseed << EOF
# Configuração de pacotes
d-i base-installer/kernel/image string $kernel
EOF

[ "$install_recommends" = false ] && echo "d-i base-installer/install-recommends boolean $install_recommends" | $save_preseed

$save_preseed << EOF
# Configuração do apt
d-i apt-setup/restricted boolean $apt_restricted
d-i apt-setup/universe boolean $apt_universe
d-i apt-setup/multiverse boolean $apt_multiverse
d-i apt-setup/backports boolean $apt_backports
EOF

[ -n "$install" ] && echo "d-i pkgsel/include string $install" | $save_preseed
[ "$upgrade" != "none" ] && echo "d-i pkgsel/upgrade select $upgrade" | $save_preseed
echo "popularity-contest popularity-contest/participate boolean false" | $save_preseed

$save_preseed << EOF
# Instalação do bootloader
EOF

[ -n "$disk" ] && echo "d-i grub-installer/bootdev string $disk" | $save_preseed || echo "d-i grub-installer/bootdev string default" | $save_preseed
[ "$force_efi_extra_removable" = true ] && echo "d-i grub-installer/force-efi-extra-removable boolean true" | $save_preseed
[ -n "$kernel_params" ] && echo "d-i debian-installer/add-kernel-opts string$kernel_params" | $save_preseed
[ "$power_off" = true ] && echo "d-i debian-installer/exit/poweroff boolean true" | $save_preseed

# Configura late_command
late_command='true'
[ -n "$in_target_script" ] && late_command="$late_command; in-target sh -c '$in_target_script'"
[ -n "$cidata" ] && late_command="$late_command; mkdir -p /target/var/lib/cloud/seed/nocloud; cp -r /cidata/. /target/var/lib/cloud/seed/nocloud/"
echo "d-i preseed/late_command string $late_command" | $save_preseed

# Baixa os arquivos necessários
# ------------------------------------------------------------------------------

if [ "$architecture" = "amd64" ]; then
    netboot_path="images/netboot"
    [[ "$version" < "18.04" ]] && netboot_path="legacy-images/netboot"
    base_url="$mirror_protocol://$mirror_host$mirror_directory/dists/$codename/main/installer-$architecture/current/$netboot_path/ubuntu-installer/$architecture"
    [ "$dry_run" = false ] && {
        download "$base_url/linux" "vmlinuz"
        download "$base_url/initrd.gz" "initrd.gz"
    } || {
        echo "[DRY-RUN] Baixando $base_url/linux para vmlinuz"
        echo "[DRY-RUN] Baixando $base_url/initrd.gz para initrd.gz"
    }
elif [ "$architecture" = "arm64" ]; then
    iso_url="$mirror_protocol://$mirror_host$mirror_directory/dists/$codename/main/installer-$architecture/current/images/netboot/mini.iso"
    [ "$dry_run" = false ] && {
        download "$iso_url" "ubuntu.iso"
        mkdir -p mnt
        mount -o loop ubuntu.iso mnt || err "Falha ao montar o ISO"
        cp mnt/vmlinuz . || err "Falha ao copiar vmlinuz"
        cp mnt/initrd.gz . || err "Falha ao copiar initrd.gz"
        umount mnt || warn "Falha ao desmontar o ISO"
        rm -rf mnt ubuntu.iso
    } || echo "[DRY-RUN] Baixando e extraindo $iso_url"
fi

# Prepara o initrd
# ------------------------------------------------------------------------------

if [ "$dry_run" = false ]; then
    gzip -d initrd.gz
    mkdir -p preseed
    mv preseed.cfg preseed/
    (cd preseed && find . | cpio -o -H newc | gzip > ../preseed.cpio.gz) || err "Falha ao criar preseed.cpio.gz"
    rm -rf preseed
    initrd_components=("preseed.cpio.gz")
    [ "$firmware" = true ] && {
        firmware_url="https://cdimage.ubuntu.com/ubuntu/releases/$version/release/firmware.tar.gz"
        download "$firmware_url" "firmware.tar.gz"
        tar -xzf firmware.tar.gz -C . firmware.cpio.gz || err "Falha ao extrair firmware"
        initrd_components+=("firmware.cpio.gz")
    }
    [ -n "$cidata" ] && {
        cp -r "$cidata" cidata
        (cd cidata && find . | cpio -o -H newc | gzip > ../cidata.cpio.gz) || err "Falha ao criar cidata.cpio.gz"
        initrd_components+=("cidata.cpio.gz")
    }
    cat "${initrd_components[@]}" initrd > initrd.gz || err "Falha ao concatenar initrd"
else
    echo "[DRY-RUN] Preparando initrd com preseed, firmware e cidata"
fi

# Configura o GRUB
# ------------------------------------------------------------------------------

[ "$dry_run" = false ] && mkdir -p "$boot_dir" || echo "[DRY-RUN] mkdir -p $boot_dir"
[ "$dry_run" = false ] && cp vmlinuz initrd.gz "$boot_dir" || echo "[DRY-RUN] Copiando vmlinuz e initrd.gz para $boot_dir"

if [ "$dry_run" = false ]; then
    if command_exists grub-mkrelpath; then
        grub_cmd="grub-mkrelpath"
    elif command_exists grub2-mkrelpath; then
        grub_cmd="grub2-mkrelpath"
    else
        err "Nenhum comando GRUB encontrado (grub-mkrelpath ou grub2-mkrelpath)"
    fi
    vmlinuz_path=$($grub_cmd "$boot_dir/vmlinuz") || err "Falha ao obter caminho relativo do vmlinuz"
    initrd_path=$($grub_cmd "$boot_dir/initrd.gz") || err "Falha ao obter caminho relativo do initrd"
    mkdir -p /etc/default/grub.d
    tee /etc/default/grub.d/zz-ubuntu-install.cfg << EOF
GRUB_DEFAULT=ubuntu-install
GRUB_TIMEOUT=$grub_timeout
GRUB_TIMEOUT_STYLE=menu
EOF
    grub_cfg="/boot/grub/grub.cfg"
    if command_exists update-grub; then
        update-grub
    elif command_exists grub2-mkconfig; then
        grub_cfg="/boot/grub2/grub.cfg"
        [ -d /sys/firmware/efi ] && grub_cfg="/boot/efi/EFI/*/grub.cfg"
        grub2-mkconfig -o "$grub_cfg"
    else
        err "Comando update-grub ou grub2-mkconfig não encontrado"
    fi
    save_grub_cfg="tee -a $grub_cfg"
else
    save_grub_cfg='cat'
    vmlinuz_path="$boot_dir/vmlinuz"
    initrd_path="$boot_dir/initrd.gz"
fi

$save_grub_cfg << EOF
menuentry 'Ubuntu Installer $version ($architecture)' --id ubuntu-install {
    insmod part_msdos
    insmod part_gpt
    insmod ext2
    insmod xfs
    insmod btrfs
    linux $vmlinuz_path boot=casper automatic-ubiquity quiet splash$kernel_params
    initrd $initrd_path
}
EOF

# Finalização
# ------------------------------------------------------------------------------

if [ "$dry_run" = false ]; then
    cleanup
    clear
    echo -e "\033[1;31m═══════════════════════════════════════\033[0m"
    tput setaf 8 ; tput setab 4 ; tput bold ; printf '%25s%s%-14s\n' "FINALIZADO!" ; tput sgr0
    echo -e "\033[1;31m═══════════════════════════════════════\033[0m"
    echo -e "\n\033[33mO servidor será reiniciado.\033[0m"
    echo -e "\033[33mPor favor, aguarde alguns minutos antes\nde tentar se reconectar ao SSH.\033[0m"
    echo -e "\033[33mAgradecemos sua compreensão e paciência.\033[0m"
    echo -ne "\n\033[31mEnter para continuar ou CTRL+C para cancelar: \033[0m"
    read -r enter
    [ "$(whoami)" != "root" ] && sudo reboot || reboot
else
    echo "[DRY-RUN] Configuração concluída. O sistema seria reiniciado aqui."
fi
