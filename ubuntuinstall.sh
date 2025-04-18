#!/bin/bash

set -eu

# Error handling function
err() {
    printf "\nError: %s.\n" "$1" 1>&2
    exit 1
}

# Warning function with a delay
warn() {
    printf "\nWarning: %s.\nContinuing with default...\n" "$1" 1>&2
    sleep 5
}

# Check if a command exists
command_exists() {
    command -v "$1" > /dev/null 2>&1
}

# Accumulate commands to run in the target system
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

# Backup a file in the target system
in_target_backup() {
    in_target "if [ ! -e \"$1.backup\" ]; then cp \"$1\" \"$1.backup\"; fi"
}

# Configure SSH daemon
configure_sshd() {
    [ -z "${sshd_config_backup+1s}" ] && in_target_backup /etc/ssh/sshd_config
    sshd_config_backup=
    in_target sed -Ei \""s/^#?$1 .+/$1 $2/"\" /etc/ssh/sshd_config
}

# Prompt for password with validation
prompt_password() {
    local prompt=

    if [ $# -gt 0 ]; then
        prompt=$1
    elif [ "$username" = root ]; then
        echo ""
        echo -e "\033[1;31m═══════════════════════════════════════════════\033[0m"
        tput setaf 8 ; tput setab 4 ; tput bold ; printf '%33s%s%-14s\n' "SET ROOT PASSWORD" ; tput sgr0
        echo -e "\033[1;31m═══════════════════════════════════════════════\033[0m"
        prompt="Root user password: "
    else
        echo ""
        echo -e "\033[1;31m═══════════════════════════════════════════════\033[0m"
        tput setaf 8 ; tput setab 4 ; tput bold ; printf '%33s%s%-14s\n' "SET USER PASSWORD" ; tput sgr0
        echo -e "\033[1;31m═══════════════════════════════════════════════\033[0m"
        prompt="Password for user $username: "
    fi

    while true; do
        echo -ne "\n\033[1;33m$prompt\033[0m"
        read -r password

        if [ -z "$password" ]; then
            echo ""
            echo -e "\033[1;31mPassword cannot be empty.\033[0m"
        elif [ "${#password}" -lt 8 ]; then
            echo ""
            echo -e "\033[1;31mPassword must be at least 8 characters long.\033[0m"
        else
            break
        fi
    done
}

# Download files with wget, curl, or busybox
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
        err 'Cannot find "wget", "curl", or "busybox wget" to download files'
    fi
}

# Set mirror proxy based on protocol
set_mirror_proxy() {
    [ -n "$mirror_proxy" ] && return

    case $mirror_protocol in
        http)
            if [ -n "${http_proxy+1s}" ]; then mirror_proxy="$http_proxy"; fi
            ;;
        https)
            if [ -n "${https_proxy+1s}" ]; then mirror_proxy="$https_proxy"; fi
            ;;
        ftp)
            if [ -n "${ftp_proxy+1s}" ]; then mirror_proxy="$ftp_proxy"; fi
            ;;
        *)
            err "Unsupported protocol: $mirror_protocol"
    esac
}

# Set security archive for Ubuntu
set_security_archive() {
    case $suite in
        trusty|xenial|bionic|focal|jammy|noble)
            security_archive="$suite-security"
            ;;
        *)
            err "Unsupported suite: $suite"
    esac
}

# Set Ubuntu version and suite
set_ubuntu_version() {
    case $1 in
        14.04|trusty)
            set_suite trusty
            ;;
        16.04|xenial)
            set_suite xenial
            ;;
        18.04|bionic)
            set_suite bionic
            ;;
        20.04|focal)
            set_suite focal
            ;;
        22.04|jammy)
            set_suite jammy
            ;;
        24.04|noble)
            set_suite noble
            ;;
        *)
            err "Unsupported version: $1"
    esac
}

set_suite() {
    suite=$1
    set_security_archive
}

# Check for cloud kernel availability
has_cloud_kernel() {
    case $suite in
        trusty)
            [ "$architecture" = amd64 ] && return
            ;;
        xenial|bionic|focal|jammy|noble)
            [ "$architecture" = amd64 ] || [ "$architecture" = arm64 ] && return
    esac

    local tmp; tmp=''; [ "$bpo_kernel" = true ] && tmp='-backports'
    warn "No cloud kernel available for $architecture/$suite$tmp"
    return 1
}

# Check for backports availability
has_backports() {
    case $suite in
        trusty|xenial|bionic|focal|jammy|noble)
            return
    esac
    warn "No backports available for $suite"
    return 1
}

# Default Ubuntu version
ubuntu_version=22.04

# Prompt for Ubuntu version
while true; do
    clear
    echo -e "\033[1;31m═══════════════════════════════════════════════\033[0m"
    tput setaf 8 ; tput setab 4 ; tput bold ; printf '%36s%s%-12s\n' "CHOOSE UBUNTU VERSION" ; tput sgr0
    echo -e "\033[1;31m═══════════════════════════════════════════════\033[0m"
    echo ""
    echo -e "\033[1;32mRecommended: Ubuntu 22.04.\033[0m"
    echo ""
    echo -ne "Choose (14.04, 16.04, 18.04, 20.04, 22.04, 24.04) [Default: 22.04]: "
    read -r user_input

    ubuntu_version=${user_input:-$ubuntu_version}

    if [[ "$ubuntu_version" =~ ^(14.04|16.04|18.04|20.04|22.04|24.04|trusty|xenial|bionic|focal|jammy|noble)$ ]]; then
        break
    else
        err "Unsupported version: $ubuntu_version"
    fi
done

# Default configuration variables
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
security_repository=mirror
account_setup=true
username=ubuntu
password=
authorized_keys_url=
sudo_with_password=false
timezone=UTC
ntp=ntp.ubuntu.com
disk_partitioning=true
disk="/dev/$(lsblk -no PKNAME "$(df /boot | grep -Eo '/dev/[a-z0-9]+')")"
force_gpt=true
efi=
esp=512
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
apt_non_free=false
apt_contrib=false
apt_src=true
apt_backports=true
cidata=

# Parse command-line arguments
while [ $# -gt 0 ]; do
    case $1 in
        --aws)
            mirror_host=cloud-images.ubuntu.com
            ntp=ntp.ubuntu.com
            ;;
        --cloudflare)
            dns='1.1.1.1 1.0.0.1'
            dns6='2606:4700:4700::1111 2606:4700:4700::1001'
            ntp=ntp.ubuntu.com
            ;;
        --interface)
            interface=$2
            shift
            ;;
        --ip)
            ip=$2
            shift
            ;;
        --netmask)
            netmask=$2
            shift
            ;;
        --gateway)
            gateway=$2
            shift
            ;;
        --dns)
            dns=$2
            shift
            ;;
        --dns6)
            dns6=$2
            shift
            ;;
        --hostname)
            hostname=$2
            shift
            ;;
        --network-console)
            network_console=true
            ;;
        --version)
            set_ubuntu Toen "$2"
            shift
            ;;
        --suite)
            set_suite "$2"
            shift
            ;;
        --mirror-protocol)
            mirror_protocol=$2
            shift
            ;;
        --mirror-host)
            mirror_host=$2
            shift
            ;;
        --mirror-directory)
            mirror_directory=${2%/}
            shift
            ;;
        --mirror-proxy|--proxy)
            mirror_proxy=$2
            shift
            ;;
        --reuse-proxy)
            set_mirror_proxy
            ;;
        --security-repository)
            security_repository=$2
            shift
            ;;
        --no-user|--no-account-setup)
            account_setup=false
            ;;
        --user|--username)
            username=$2
            shift
            ;;
        --password)
            password=$2
            shift
            ;;
        --authorized-keys-url)
            authorized_keys_url=$2
            shift
            ;;
        --sudo-with-password)
            sudo_with_password=true
            ;;
        --timezone)
            timezone=$2
            shift
            ;;
        --ntp)
            ntp=$2
            shift
            ;;
        --no-part|--no-disk-partitioning)
            disk_partitioning=false
            ;;
        --force-lowmem)
            [ "$2" != 0 ] && [ "$2" != 1 ] && [ "$2" != 2 ] && err 'Low memory level can only be 0, 1 or 2'
            force_lowmem=$2
            shift
            ;;
        --disk)
            disk=$2
            shift
            ;;
        --no-force-gpt)
            force_gpt=false
            ;;
        --bios)
            efi=false
            ;;
        --efi)
            efi=true
            ;;
        --esp)
            esp=$2
            shift
            ;;
        --filesystem)
            filesystem=$2
            shift
            ;;
        --kernel)
            kernel=$2
            shift
            ;;
        --cloud-kernel)
            cloud_kernel=true
            ;;
        --bpo-kernel)
            bpo_kernel=true
            ;;
        --apt-non-free)
            apt_non_free=true
            apt_contrib=true
            ;;
        --apt-contrib)
            apt_contrib=true
            ;;
        --apt-src)
            apt_src=true
            ;;
        --apt-backports)
            apt_backports=true
            ;;
        --no-apt-non-free)
            apt_non_free=false
            ;;
        --no-apt-contrib)
            apt_contrib=false
            apt_non_free=false
            ;;
        --no-apt-src)
            apt_src=false
            ;;
        --no-apt-backports)
            apt_backports=false
            ;;
        --no-install-recommends)
            install_recommends=true
            ;;
        --install)
            install=$2
            shift
            ;;
        --no-upgrade)
            upgrade=none
            ;;
        --safe-upgrade)
            upgrade=safe-upgrade
            ;;
        --full-upgrade)
            upgrade=full-upgrade
            ;;
        --bbr)
            bbr=true
            ;;
        --ssh-port)
            ssh_port=$2
            shift
            ;;
        --hold)
            hold=true
            ;;
        --power-off)
            power_off=true
            ;;
        --architecture)
            architecture=$2
            shift
            ;;
        --firmware)
            firmware=true
            ;;
        --no-force-efi-extra-removable)
            force_efi_extra_removable=false
            ;;
        --grub-timeout)
            grub_timeout=$2
            shift
            ;;
        --dry-run)
            dry_run=true
            ;;
        --cidata)
            cidata=$(realpath "$2")
            [ ! -f "$cidata/meta-data" ] && err 'No "meta-data" file found in the cloud-init directory'
            [ ! -f "$cidata/user-data" ] && err 'No "user-data" file found in the cloud-init directory'
            shift
            ;;
        *)
            err "Unknown option: \"$1\""
    esac
    shift
done

# Detect architecture if not specified
[ -z "$architecture" ] && {
    architecture=$(dpkg --print-architecture 2> /dev/null) || {
        case $(uname -m) in
            x86_64)
                architecture=amd64
                ;;
            aarch64)
                architecture=arm64
                ;;
            i386)
                architecture=i386
                ;;
            *)
                err 'No "--architecture" specified'
        esac
    }
}

# Set default kernel
[ -z "$kernel" ] && {
    kernel="linux-image-generic"
    [ "$cloud_kernel" = true ] && has_cloud_kernel && kernel="linux-image-virtual"
    [ "$bpo_kernel" = true ] && has_backports && install="$kernel/$suite-backports $install"
}

# Verify authorized keys URL
[ -n "$authorized_keys_url" ] && ! download "$authorized_keys_url" /dev/null &&
err "Failed to download SSH authorized public keys from \"$authorized_keys_url\""

# Ubuntu-specific apt components
apt_components=main,universe
[ "$apt_contrib" = true ] && apt_components="$apt_components,multiverse"
[ "$apt_non_free" = true ] && apt_components="$apt_components,multiverse"

apt_services=updates
[ "$apt_backports" = true ] && apt_services="$apt_services,backports"

# Set up installer directory
installer_directory="/boot/ubuntu-$suite"
save_preseed='cat'
[ "$dry_run" = false ] && {
    [ "$(id -u)" -ne 0 ] && err 'Root privilege is required'
    rm -rf "$installer_directory"
    mkdir -p "$installer_directory"
    cd "$installer_directory"
    save_preseed='tee -a preseed.cfg'
}

# Prompt for password if account setup is enabled
if [ "$account_setup" = true ]; then
    prompt_password
elif [ "$network_console" = true ] && [ -z "$authorized_keys_url" ]; then
    prompt_password "Choose a password for the SSH network console installer user: "
fi

# Write preseed configuration
$save_preseed << EOF
# Localization
d-i debian-installer/language string en
d-i debian-installer/country string US
d-i debian-installer/locale string en_US.UTF-8
d-i keyboard-configuration/xkb-keymap select us

# Network configuration
d-i netcfg/choose_interface select $interface
EOF

# Configure static IP if provided
[ -n "$ip" ] && {
    echo 'd-i netcfg/disable_autoconfig boolean true' | $save_preseed
    echo "d-i netcfg/get_ipaddress string $ip" | $save_preseed
    [ -n "$netmask" ] && echo "d-i netcfg/get_netmask string $netmask" | $save_preseed
    [ -n "$gateway" ] && echo "d-i netcfg/get_gateway string $gateway" | $save_preseed
    [ -n "$dns" ] && echo "d-i netcfg/get_nameservers string $dns" | $save_preseed
    [ -n "$dns6" ] && echo "d-i netcfg/get_nameservers string $dns6" | $save_preseed
    echo 'd-i netcfg/confirm_static boolean true' | $save_preseed
}

# Set hostname and domain
if [ -n "$hostname" ]; then
    echo "d-i netcfg/hostname string $hostname" | $save_preseed
    hostname=ubuntu
    domain=
else
    hostname=$(cat /proc/sys/kernel/hostname)
    domain=$(cat /proc/sys/kernel/domainname)
    if [ "$domain" = '(none)' ]; then
        domain=
    else
        domain=" $domain"
    fi
fi

$save_preseed << EOF
d-i netcfg/get_hostname string $hostname
d-i netcfg/get_domain string$domain
EOF

echo 'd-i hw-detect/load_firmware boolean true' | $save_preseed

# Configure network console if enabled
[ "$network_console" = true ] && {
    $save_preseed << 'EOF'
# Network console
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

# Mirror settings
$save_preseed << EOF
# Mirror settings
d-i mirror/country string manual
d-i mirror/protocol string $mirror_protocol
d-i mirror/$mirror_protocol/hostname string $mirror_host
d-i mirror/$mirror_protocol/directory string $mirror_directory
d-i mirror/$mirror_protocol/proxy string $mirror_proxy
d-i mirror/suite string $suite
EOF

# Account setup
[ "$account_setup" = true ] && {
    password_hash=$(mkpasswd -m sha-512 "$password" 2> /dev/null) ||
    password_hash=$(openssl passwd -6 "$password" 2> /dev/null) ||
    password_hash=$(busybox mkpasswd -m sha512 "$password" 2> /dev/null) || {
        for python in python3 python python2; do
            password_hash=$("$python" -c 'import crypt, sys; print(crypt.crypt(sys.argv[1], crypt.mksalt(crypt.METHOD_SHA512)))' "$password" 2> /dev/null) && break
        done
    }

    $save_preseed << 'EOF'
# Account setup
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

# Configure SSH port if specified
[ -n "$ssh_port" ] && configure_sshd Port "$ssh_port"

# Clock and timezone setup
$save_preseed << EOF
# Clock and time zone setup
d-i time/zone string $timezone
d-i clock-setup/utc boolean true
d-i clock-setup/ntp boolean true
d-i clock-setup/ntp-server string $ntp

# Partitioning
EOF

# Disk partitioning
[ "$disk_partitioning" = true ] && {
    $save_preseed << 'EOF'
d-i partman-auto/method string regular
EOF
    if [ -n "$disk" ]; then
        echo "d-i partman-auto/disk string $disk" | $save_preseed
    else
        echo 'd-i partman/early_command string debconf-set partman-auto/disk "$(list-devices disk | head -n 1)"' | $save_preseed
    fi
}

# Force GPT if specified
[ "$force_gpt" = true ] && {
    $save_preseed << 'EOF'
d-i partman-partitioning/choose_label string gpt
d-i partman-partitioning/default_label string gpt
EOF
}

# Partitioning recipe
[ "$disk_partitioning" = true ] && {
    echo "d-i partman/default_filesystem string $filesystem" | $save_preseed

    [ -z "$efi" ] && {
        efi=false
        [ -d /sys/firmware/efi ] && efi=true
    }

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
    if [ "$efi" = true ]; then
        echo 'd-i partman-efi/non_efi_system boolean true' | $save_preseed
    fi

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

# Base system installation
$save_preseed << EOF
# Base system installation
d-i base-installer/kernel/image string $kernel
EOF

[ "$install_recommends" = false ] && echo "d-i base-installer/install-recommends boolean $install_recommends" | $save_preseed

# Apt setup
[ "$security_repository" = mirror ] && security_repository=$mirror_protocol://$mirror_host${mirror_directory%/*}/ubuntu

$save_preseed << EOF
# Apt setup
d-i apt-setup/universe boolean true
d-i apt-setup/multiverse boolean $apt_contrib
d-i apt-setup/restricted boolean $apt_non_free
d-i apt-setup/enable-source-repositories boolean $apt_src
d-i apt-setup/services-select multiselect $apt_services
EOF

# Security repository
[ -n "$security_archive" ] && {
    $save_preseed << EOF
d-i apt-setup/local0/repository string $security_repository $security_archive $apt_components
d-i apt-setup/local0/source boolean $apt_src
EOF
}

# Package selection
$save_preseed << 'EOF'
# Package selection
tasksel tasksel/first multiselect standard, ubuntu-server
EOF

install="$install ca-certificates openssh-server wget curl sudo"
[ -n "$cidata" ] && install="$install cloud-init"

[ -n "$install" ] && echo "d-i pkgsel/include string $install" | $save_preseed
[ -n "$upgrade" ] && echo "d-i pkgsel/upgrade select $upgrade" | $save_preseed

$save_preseed << 'EOF'
popularity-contest popularity-contest/participate boolean false

# Boot loader installation
EOF

# GRUB installation
if [ -n "$disk" ]; then
    echo "d-i grub-installer/bootdev string $disk" | $save_preseed
else
    echo 'd-i grub-installer/bootdev string default' | $save_preseed
fi

[ "$force_efi_extra_removable" = true ] && echo 'd-i grub-installer/force-efi-extra-removable boolean true' | $save_preseed
[ -n "$kernel_params" ] && echo "d-i debian-installer/add-kernel-opts string$kernel_params" | $save_preseed

$save_preseed << 'EOF'
# Finishing up the installation
EOF

[ "$hold" = false ] && echo 'd-i finish-install/reboot_in_progress note' | $save_preseed

# Enable BBR if specified
[ "$bbr" = true ] && in_target '{ echo "net.core.default_qdisc=fq"; echo "net.ipv4.tcp_congestion_control=bbr"; } > /etc/sysctl.d/bbr.conf'

# Cloud-init configuration
[ -n "$cidata" ] && in_target 'echo "{ datasource_list: [ NoCloud ], datasource: { NoCloud: { fs_label: ~ } } }" > /etc/cloud/cloud.cfg.d/99_ubuntu.cfg'

# Late commands
late_command='true'
[ -n "$in_target_script" ] && late_command="$late_command; in-target sh -c '$in_target_script'"
[ -n "$cidata" ] && late_command="$late_command; mkdir -p /target/var/lib/cloud/seed/nocloud; cp -r /cidata/. /target/var/lib/cloud/seed/nocloud/"

echo "d-i preseed/late_command string $late_command" | $save_preseed

[ "$power_off" = true ] && echo 'd-i debian-installer/exit/poweroff boolean true' | $save_preseed

# GRUB configuration
save_grub_cfg='cat'
[ "$dry_run" = false ] && {
    base_url="$mirror_protocol://$mirror_host$mirror_directory/dists/$suite/main/installer-$architecture/current/images/netboot/ubuntu-installer/$architecture"
    firmware_url="https://cdimage.ubuntu.com/netboot/$suite/firmware.tar.gz"

    download "$base_url/linux" linux
    download "$base_url/initrd.gz" initrd.gz
    [ "$firmware" = true ] && download "$firmware_url" firmware.tar.gz

    gzip -d initrd.gz
    echo preseed.cfg | cpio -o -H newc -A -F initrd

    if [ -n "$cidata" ]; then
        cp -r "$cidata" cidata
        find cidata | cpio -o -H newc -A -F initrd
    fi

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
        tmp=$(mktemp)
        grep -vF zz_ubuntu /etc/default/grub > "$tmp"
        cat "$tmp" > /etc/default/grub
        rm "$tmp"
        echo 'zz_ubuntu=/etc/default/grub.d/zz-ubuntu.cfg; if [ -f "$zz_ubuntu" ]; then . "$zz_ubuntu"; fi' >> /etc/default/grub
        grub_cfg=/boot/grub2/grub.cfg
        [ -d /sys/firmware/efi ] && grub_cfg=/boot/efi/EFI/*/grub.cfg
        grub2-mkconfig -o "$grub_cfg"
    elif command_exists grub-mkconfig; then
        tmp=$(mktemp)
        grep -vF zz_ubuntu /etc/default/grub > "$tmp"
        cat "$tmp" > /etc/default/grub
        rm "$tmp"
        echo 'zz_ubuntu=/etc/default/grub.d/zz-ubuntu.cfg; if [ -f "$zz_ubuntu" ]; then . "$zz_ubuntu"; fi' >> /etc/default/grub
        grub_cfg=/boot/grub/grub.cfg
        grub-mkconfig -o "$grub_cfg"
    else
        err 'Could not find "update-grub" or "grub2-mkconfig" or "grub-mkconfig" command'
    fi

    save_grub_cfg="tee -a $grub_cfg"
}

# Generate GRUB menu entry
mkrelpath=$installer_directory
[ "$dry_run" = true ] && mkrelpath=/boot
installer_directory=$(grub-mkrelpath "$mkrelpath" 2> /dev/null) ||
installer_directory=$(grub2-mkrelpath "$mkrelpath" 2> /dev/null) || {
    err 'Could not find "grub-mkrelpath" or "grub2-mkrelpath" command'
}
[ "$dry_run" = true ] && installer_directory="$installer_directory/ubuntu-$suite"

kernel_params="$kernel_params lowmem/low=1"
[ -n "$force_lowmem" ] && kernel_params="$kernel_params lowmem=+$force_lowmem"

initrd="$installer_directory/initrd.gz"
[ "$firmware" = true ] && initrd="$initrd $installer_directory/firmware.tar.gz"

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

# Final message and reboot
clear
echo ""
echo -e "\033[1;31m═══════════════════════════════════════\033[0m"
tput setaf 8 ; tput setab 4 ; tput bold ; printf '%25s%s%-14s\n' "COMPLETED!" ; tput sgr0
echo -e "\033[1;31m═══════════════════════════════════════\033[0m"
echo ""
echo -e "\033[33mThe server will now reboot.\033[0m"
echo -e "\033[33mPlease wait a few minutes before\nattempting to reconnect via SSH.\033[0m"
echo -e "\033[33mThank you for your patience.\033[0m"
echo ""
echo -ne "\033[31mPress Enter to continue or CTRL+C to cancel: \033[0m"; read -r enter

# Reboot the system
if [ "$(whoami)" != "root" ]; then 
    sudo reboot
else
    reboot
fi
