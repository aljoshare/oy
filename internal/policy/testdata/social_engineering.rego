package oy

import rego.v1

# METADATA
# title: Classic Social Engineering
# description: Detects classic phishing patterns such as account verification prompts, credential requests, and urgency framing.
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

# METADATA
# title: Agent-Targeted Social Engineering
# description: Detects framing attacks that exploit AI agent helpfulness, urgency, or authority claims to bypass safety checks or escalate privileges.
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
