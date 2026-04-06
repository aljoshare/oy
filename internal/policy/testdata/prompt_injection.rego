package oy

import rego.v1

# Indirect prompt injection: instruction override patterns
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

# Context/memory poisoning — attempts to modify persistent agent memory
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

# Invisible Unicode character injection — characters invisible to humans but read by LLMs.
# Detects zero-width spaces/joiners (U+200B–U+200D), BOM (U+FEFF), word joiner (U+2060),
# bidirectional control characters (U+202A–U+202E, U+2066–U+2069), and soft hyphen (U+00AD).
# These were used in real attacks against GitHub Copilot and Cursor in 2025.
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
