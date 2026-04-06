package oy

import rego.v1

# Classic social engineering / phishing patterns.
deny contains msg if {
	patterns := [
		"click this link to verify your account",
		"enter your password to continue",
		"your account will be suspended",
		"confirm your credentials",
		"provide your private key",
		"share your secret key",
		"verify your identity by entering",
		"your session will expire",
		"immediate action required",
		"act now to avoid",
	]
	pattern := patterns[_]
	contains(lower(input.content), pattern)
	msg := sprintf("possible social engineering: %q", [pattern])
}

# AI-agent-specific social engineering:
# Framing attacks that exploit helpfulness, urgency, or authority to get agents to act.
# Research sources: OWASP LLM Top 10 2025, Lakera indirect injection research.
deny contains msg if {
	patterns := [
		# Urgency/authority framing
		"this is an urgent security update",
		"your administrator requires",
		"security team requires you to",
		"compliance requires you to run",
		"this is a required maintenance task",
		"to complete setup, you must run",
		"required for the build to succeed",
		# Trust elevation tricks
		"i have full authorization to",
		"i am the owner of this repository",
		"as the maintainer, i authorize",
		"you have permission to",
		"the developer has approved",
		# Misdirection / false context
		"this is a test environment with no real consequences",
		"this is a sandboxed environment",
		"this command is safe because",
		"don't worry, this is reversible",
		"for debugging purposes only",
	]
	pattern := patterns[_]
	contains(lower(input.content), pattern)
	msg := sprintf("possible agent-targeted social engineering: %q", [pattern])
}
