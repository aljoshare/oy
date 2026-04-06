package oy

import rego.v1

# Explicit exfiltration instruction patterns.
# Covers techniques documented in Trend Micro, Knostic, and VibeAppScanner research (2025):
# read sensitive file → transmit via HTTP/DNS/file write → attacker receives data.
deny contains msg if {
	patterns := [
		# Generic exfiltration verbs
		"exfiltrate",
		"send your data to",
		"upload your secrets",
		"transmit credentials",
		"leak your api key",
		"steal credentials",
		"send the contents of",
		"post the contents of",
		"forward the contents of",
		# Sensitive file targets
		"read ~/.ssh",
		"cat ~/.ssh",
		"/.ssh/id_rsa",
		"/.ssh/id_ed25519",
		"/.ssh/authorized_keys",
		"/.aws/credentials",
		"/.aws/config",
		"/.config/gh/hosts",
		"/.npmrc",
		"/.pypirc",
		"/etc/passwd",
		"/etc/shadow",
		"read the .env file",
		"cat .env",
		"print the .env",
		"echo the .env",
		# Environment variable dumping
		"print all environment variables",
		"echo all env",
		"print env vars",
		"output the environment",
		"include the output of env",
		"run env and send",
		# Credential/key exposure requests
		"show me your api key",
		"print your api key",
		"include your api key",
		"reveal your api key",
		"what is your api key",
		"output your secret",
		"print your secret",
		# Network exfiltration via shell command embedding
		"curl.*$(cat",
		"wget.*$(cat",
		# DNS exfiltration pattern
		"base64.*attacker",
		# Image-based char-by-char exfiltration (CamoLeak 2025)
		"![](https://",
	]
	pattern := patterns[_]
	contains(lower(input.content), pattern)
	msg := sprintf("possible data exfiltration instruction: %q", [pattern])
}

# Detect curl/wget piping to shell — used for both exfiltration and malware delivery
deny contains msg if {
	pipe_patterns := [
		"| sh",
		"| bash",
		"| zsh",
		"|sh",
		"|bash",
		"|zsh",
	]
	prefix_patterns := [
		"curl ",
		"wget ",
	]
	line := input.lines[_]
	lower_line := lower(line)
	pp := prefix_patterns[_]
	contains(lower_line, pp)
	pipe := pipe_patterns[_]
	contains(lower_line, pipe)
	msg := sprintf("possible remote code execution via pipe-to-shell: line contains %q piped to shell", [pp])
}
