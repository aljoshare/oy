package oy

import rego.v1

# METADATA
# title: Instruction Override
# description: Detects indirect prompt injection via instruction override patterns such as "ignore previous instructions" or "admin mode activated".
deny contains msg if {
	patterns := [
		"ignore previous instructions",
		"ignore all previous",
		"ignore all prior",
		"disregard your instructions",
		"disregard previous instructions",
		"disregard all prior",
		"forget your instructions",
		"override your instructions",
		"your instructions have been updated",
		"new instructions follow",
		"your new instructions",
		"your real instructions",
		"instructions have changed",
		"updated instructions:",
		"the following instructions replace",
		"supersede all previous",
		"end of system prompt",
		"new system prompt",
		"system prompt override",
		"[system override]",
		"[system]: new instructions",
		"admin mode activated",
		"safety constraints are suspended",
		"previous instructions are void",
		"act as if you",
		"pretend you are",
		"you must now follow",
	]
	pattern := patterns[_]
	contains(lower(input.content), pattern)
	msg := sprintf("possible prompt injection (instruction override): %q", [pattern])
}

# METADATA
# title: Context and Memory Poisoning
# description: Detects attempts to modify persistent agent memory files such as CLAUDE.md or .cursorrules.
deny contains msg if {
	patterns := [
		"update your claude.md",
		"update your memory.md",
		"update your agents.md",
		"write to your memory",
		"add to your persistent memory",
		"remember for all future sessions",
		"remember this permanently",
		"store this in your memory",
		"update your system instructions",
		"modify your configuration file",
		"update your .cursorrules",
		"update your rules file",
	]
	pattern := patterns[_]
	contains(lower(input.content), pattern)
	msg := sprintf("possible context/memory poisoning: %q", [pattern])
}

# METADATA
# title: Invisible Unicode Injection
# description: Detects zero-width spaces, bidirectional control characters, and other invisible Unicode used to hide instructions from human reviewers.
deny contains msg if {
	suspicious := [
		# Zero-width space (U+200B)
		"\u200b",
		# Zero-width non-joiner (U+200C)
		"\u200c",
		# Zero-width joiner (U+200D)
		"\u200d",
		# BOM / zero-width no-break space (U+FEFF)
		"\ufeff",
		# Word joiner (U+2060)
		"\u2060",
		# Left-to-right embedding (U+202A)
		"\u202a",
		# Right-to-left embedding (U+202B)
		"\u202b",
		# Pop directional formatting (U+202C)
		"\u202c",
		# Left-to-right override (U+202D)
		"\u202d",
		# Right-to-left override (U+202E)
		"\u202e",
		# Left-to-right isolate (U+2066)
		"\u2066",
		# Right-to-left isolate (U+2067)
		"\u2067",
		# First strong isolate (U+2068)
		"\u2068",
		# Pop directional isolate (U+2069)
		"\u2069",
		# Soft hyphen (U+00AD) — invisible but parsed by LLMs
		"\u00ad",
	]
	ch := suspicious[_]
	contains(input.content, ch)
	msg := "invisible/bidi Unicode character detected (possible hidden instruction injection via zero-width or directional override character)"
}
