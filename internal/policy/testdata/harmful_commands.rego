package oy

import rego.v1

# Destructive shell commands — disk wipe, fork bomb, mass permission change.
deny contains msg if {
	patterns := [
		"rm -rf /",
		"rm -rf /*",
		"rm --no-preserve-root",
		"mkfs",
		"dd if=/dev/zero",
		"dd if=/dev/random",
		":(){:|:&};:",
		"chmod -R 777 /",
		"> /dev/sda",
		"shred /dev",
	]
	pattern := patterns[_]
	contains(input.content, pattern)
	msg := sprintf("potentially destructive shell command: %q", [pattern])
}

# Privilege escalation patterns.
# Covers sudo abuse, setuid bit, sudoers tampering, firewall/SELinux disabling.
# Related to active CVEs CVE-2025-32463 and CVE-2025-32462 and AI agent abuse scenarios.
deny contains msg if {
	patterns := [
		"sudo chmod 777",
		"chmod u+s /bin/bash",
		"chmod +s /bin/bash",
		"chmod u+s /bin/sh",
		"chmod +s /bin/sh",
		"sudo ufw disable",
		"sudo iptables -f",
		"sudo iptables --flush",
		"setenforce 0",
		"systemctl stop apparmor",
		"systemctl disable apparmor",
		"systemctl stop firewalld",
		"systemctl disable firewalld",
		"systemctl stop ufw",
		"nopasswd: all",
		"all=(all) nopasswd",
		"sudo visudo",
		"sudo usermod -ag sudo",
		"sudo usermod -a -g sudo",
		"sudo adduser.*sudo",
	]
	pattern := patterns[_]
	contains(lower(input.content), pattern)
	msg := sprintf("possible privilege escalation command: %q", [pattern])
}

# Persistence attack patterns.
# Covers SSH key injection, cron backdoors, shell profile poisoning,
# and git hook hijacking as documented in Cisco and Penligent Labs research (2025).
deny contains msg if {
	patterns := [
		"authorized_keys",
		"crontab -l",
		"/etc/cron.d",
		"/etc/crontab",
		".bashrc",
		".bash_profile",
		".zshrc",
		".profile",
		"hookspath",
		"hooks-path",
		".git/hooks",
		"systemd.*enable",
		"/etc/init.d",
		"/etc/rc.local",
	]
	pattern := patterns[_]
	# Only flag if combined with an HTTP/shell/write action nearby
	contains(lower(input.content), pattern)
	write_or_net := ["curl", "wget", "echo >>", "tee -a", ">>", "write", "append", "install"]
	action := write_or_net[_]
	contains(lower(input.content), action)
	msg := sprintf("possible persistence attack: %q combined with a write/network action", [pattern])
}

# Supply chain / dependency confusion patterns.
# Covers malicious registry redirection and pipe-to-shell installs.
# Informed by Shai-Hulud worm (CISA, Sep 2025) and s1ngularity npm attack (Aug 2025).
deny contains msg if {
	patterns := [
		"--index-url http",
		"--extra-index-url http",
		"--registry http://",
		"--registry https://",
		"pip install.*--index-url",
		"npm install.*--registry",
		"wget.*install.sh",
		"curl.*install.sh",
		"bash install.sh",
		"sh install.sh",
		"--dangerously-skip-permissions",
		"--yolo",
		"--trust-all-tools",
	]
	pattern := patterns[_]
	contains(lower(input.content), pattern)
	msg := sprintf("possible supply chain / dependency confusion attack: %q", [pattern])
}
