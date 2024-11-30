#!/bin/bash

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

echo "Starting Linux hardening process..."

# Update and upgrade the system
echo "Updating and upgrading the system..."
apt-get update -y && apt-get upgrade -y

# Disable root login via SSH
echo "Disabling root login via SSH..."
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd

# Disable password authentication for SSH (key-based only)
echo "Disabling password authentication for SSH..."
sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd

# Configure SSH idle timeout and limit retries
echo "Configuring SSH timeout and retry limits..."
echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
echo "ClientAliveCountMax 2" >> /etc/ssh/sshd_config
echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
systemctl restart sshd

# Set up a strong password policy
echo "Setting up a strong password policy..."
apt-get install -y libpam-pwquality
cat <<EOF >/etc/security/pwquality.conf
minlen = 12
minclass = 4
maxrepeat = 2
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
EOF

# Enable audit logs
echo "Enabling audit logs..."
apt-get install -y auditd
systemctl enable auditd
systemctl start auditd

# Configure audit rules
echo "Configuring audit rules..."
cat <<EOF >/etc/audit/rules.d/hardening.rules
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/ssh/sshd_config -p wa -k ssh_config
EOF
service auditd restart

# Restrict access to the su command
echo "Restricting access to the su command..."
groupadd wheel
usermod -aG wheel $(logname)
dpkg-statoverride --update --add root wheel 4750 /bin/su

# Disable unused filesystems
echo "Disabling unused filesystems..."
echo "install cramfs /bin/false" >>/etc/modprobe.d/disable-filesystems.conf
echo "install freevxfs /bin/false" >>/etc/modprobe.d/disable-filesystems.conf
echo "install jffs2 /bin/false" >>/etc/modprobe.d/disable-filesystems.conf
echo "install hfs /bin/false" >>/etc/modprobe.d/disable-filesystems.conf
echo "install hfsplus /bin/false" >>/etc/modprobe.d/disable-filesystems.conf
echo "install udf /bin/false" >>/etc/modprobe.d/disable-filesystems.conf

# Enable automatic updates
echo "Enabling automatic updates..."
apt-get install -y unattended-upgrades
dpkg-reconfigure --priority=low unattended-upgrades

# Set up a firewall with UFW
echo "Setting up a firewall with UFW..."
apt-get install -y ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw enable

# Secure shared memory
echo "Securing shared memory..."
echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >>/etc/fstab
mount -o remount /run/shm

# Disable core dumps
echo "Disabling core dumps..."
echo "* hard core 0" >>/etc/security/limits.conf
echo "fs.suid_dumpable = 0" >>/etc/sysctl.conf
sysctl -p

# Configure sysctl for network hardening
echo "Configuring sysctl for network hardening..."
cat <<EOF >/etc/sysctl.d/99-hardening.conf
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.tcp_timestamps = 0
EOF
sysctl --system

# Remove unnecessary packages
echo "Removing unnecessary packages..."
apt-get autoremove -y
apt-get autoclean -y

# Disable unwanted services
echo "Disabling unwanted services..."
systemctl disable avahi-daemon
systemctl stop avahi-daemon

# Install and configure Fail2Ban
echo "Installing and configuring Fail2Ban..."
apt-get install -y fail2ban
cat <<EOF >/etc/fail2ban/jail.local
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF
systemctl enable fail2ban
systemctl start fail2ban

# Install ClamAV for malware scanning
echo "Installing ClamAV for malware scanning..."
apt-get install -y clamav
freshclam
systemctl enable clamav-freshclam
systemctl start clamav-freshclam

# Enforce apparmor profiles
echo "Enforcing AppArmor profiles..."
apt-get install -y apparmor apparmor-utils
aa-enforce /etc/apparmor.d/*

echo "Linux hardening process completed successfully."
