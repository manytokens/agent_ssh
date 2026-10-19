#!/bin/sh
set -eu
ssh-keygen -A
mkdir -p /root/.ssh /run/sshd
cp /workspace/work/integration/relay.pub /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
cat >/etc/ssh/sshd_config <<'EOF'
Port 22
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowTcpForwarding yes
GatewayPorts no
PermitTTY yes
PrintMotd yes
PrintLastLog yes
Subsystem sftp internal-sftp
LogLevel VERBOSE
EOF
printf 'ASSH_TEST_REAL_MOTD\n' >/etc/motd
printf "printf 'ASSH_TEST_PROFILE_ONCE\\n'\nPS1='ASSH_TEST_PROMPT> '\n" >/etc/profile.d/assh-test.sh
sed -i '/^root:/s#:/bin/[^:]*$#:/bin/bash#' /etc/passwd
# Alpine root starts locked; public-key-only access remains required by sshd.
passwd -u root >/dev/null 2>&1 || true
exec /usr/sbin/sshd -D -e
