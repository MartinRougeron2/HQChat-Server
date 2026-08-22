#!/usr/bin/env bash
#
# harden-vm.sh — baseline host hardening for the DissQus VM (Ubuntu 24.04).
# Idempotent; safe to re-run. Run as root/sudo on the VM.
#
#   sudo deploy/scripts/harden-vm.sh
#
# What it does (a pragmatic CIS-flavoured baseline):
#   1. ufw firewall: SSH (rate-limited) + 80/443 ONLY from Cloudflare IPs.
#   2. SSH: no root login, no password auth, no empty passwords (key-only).
#   3. fail2ban on sshd.
#   4. Automatic security updates (unattended-upgrades).
#   5. Kernel/network sysctl hardening.
#   6. Docker daemon: rotated logs, live-restore, no-new-privileges by default.
#
# SAFETY: step 2 disables SSH password auth. Make sure your key works FIRST.
# Pass --keep-password-auth to skip that one change.
#
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "❌ run with sudo/root" >&2; exit 1; }
KEEP_PW_AUTH=false; [[ "${1:-}" == "--keep-password-auth" ]] && KEEP_PW_AUTH=true

echo "── 1/6 firewall (ufw, Cloudflare-only 80/443) ───────────────────"
apt-get install -y ufw curl >/dev/null
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw limit OpenSSH >/dev/null               # rate-limit SSH brute force
# Only Cloudflare may reach the origin web ports (everyone else is denied).
for url in https://www.cloudflare.com/ips-v4 https://www.cloudflare.com/ips-v6; do
  while read -r cidr; do
    [[ -z "$cidr" ]] && continue
    ufw allow from "$cidr" to any port 443 proto tcp >/dev/null
    ufw allow from "$cidr" to any port 80  proto tcp >/dev/null
  done < <(curl -fsS "$url")
done
ufw --force enable >/dev/null
echo "   ufw enabled: SSH limited; 80/443 Cloudflare-only."

echo "── 2/6 SSH hardening ────────────────────────────────────────────"
# ORDER MATTERS: KbdInteractiveAuthentication no disables the keyboard-interactive
# channel that TOTP rides on. Run this script BEFORE enrolling a deploy user in
# google-authenticator (docs/runbooks/deploy.md §7) — running it afterwards
# silently turns the OTP gate off, and the file name (99-) sorts last, so it wins.
cat > /etc/ssh/sshd_config.d/99-hardening.conf <<EOF
PermitRootLogin no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
if ! $KEEP_PW_AUTH; then
  echo "PasswordAuthentication no" >> /etc/ssh/sshd_config.d/99-hardening.conf
  echo "   key-only SSH enforced (re-run with --keep-password-auth to keep passwords)."
fi
sshd -t && systemctl reload ssh 2>/dev/null || systemctl reload sshd

echo "── 3/6 fail2ban ─────────────────────────────────────────────────"
apt-get install -y fail2ban >/dev/null
cat > /etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]
enabled = true
maxretry = 4
bantime = 1h
findtime = 10m
EOF
systemctl enable --now fail2ban >/dev/null 2>&1 || true

echo "── 4/6 unattended security upgrades ─────────────────────────────"
apt-get install -y unattended-upgrades >/dev/null
echo 'APT::Periodic::Update-Package-Lists "1";'  > /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Unattended-Upgrade "1";'   >> /etc/apt/apt.conf.d/20auto-upgrades

echo "── 5/6 kernel/network sysctl ────────────────────────────────────"
cat > /etc/sysctl.d/99-hardening.conf <<EOF
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.log_martians=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_source_route=0
kernel.randomize_va_space=2
fs.protected_hardlinks=1
fs.protected_symlinks=1
EOF
sysctl --system >/dev/null

echo "── 6/6 docker daemon ────────────────────────────────────────────"
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<EOF
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "5" },
  "live-restore": true,
  "no-new-privileges": true,
  "userland-proxy": false
}
EOF
systemctl restart docker || echo "   (restart docker manually if it's busy)"

echo
echo "✅ VM hardened. Verify: 'ufw status verbose', 'fail2ban-client status sshd'."
echo "   Re-run after Cloudflare changes its IP ranges to refresh the firewall."
