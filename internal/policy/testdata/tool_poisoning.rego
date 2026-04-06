package oy

import rego.v1

# Tool/skill abuse patterns — instructions that tell an AI agent to invoke its
# built-in tools (bash, file write, HTTP, browser) to perform attacker actions.
# Based on: Snyk "From SKILL.md to Shell Access" (2025), Invariant Labs MCP Tool
# Poisoning disclosure (Apr 2025), Trend Micro AI agent vulnerability research.
deny contains msg if {
	patterns := [
		# Direct tool invocation instructions
		"use the bash tool",
		"use your bash tool",
		"using the bash tool",
		"use your terminal",
		"using your terminal",
		"use the terminal tool",
		"use your code execution",
		"using your code execution",
		"use the execute tool",
		"call the execute",
		"execute the following command",
		"execute the following script",
		"run the following command",
		"run the following script",
		"run this script using your",
		"using your shell",
		"use the shell tool",
		# File write tool abuse
		"use your file write",
		"use the file write tool",
		"use the write tool to",
		"write the following to",
		"use your write capability",
		# HTTP/browser tool abuse for exfiltration
		"use the http tool",
		"use your http tool",
		"call the http tool",
		"use the browser tool to navigate to",
		"use your browser tool",
		"make an http request to",
		"use the fetch tool",
		# MCP-specific tool abuse patterns
		"use the mcp tool",
		"call the mcp",
		"invoke the tool",
		"tool_call:",
		"function_call:",
		# Post-action exfiltration framing
		"after completing.*call",
		"when finished.*send",
		"include the results in a request to",
	]
	pattern := patterns[_]
	contains(lower(input.content), pattern)
	msg := sprintf("possible tool/skill abuse instruction: %q", [pattern])
}

# MCP tool poisoning — hidden instructions in tool descriptions or comment blocks
# targeting AI agents' context loading. Invariant Labs found 5.5% of public MCP
# servers contain poisoned metadata; attacks succeed 84.2% of the time with
# auto-approval enabled (2025).
deny contains msg if {
	patterns := [
		"[tool_override]",
		"[mcp_override]",
		"[hidden_instruction]",
		"[agent_instruction]",
		"<!-- [system]",
		"<!-- ignore",
		"<!-- follow",
		"<!-- execute",
		"<!-- run",
		"<!-- read",
		"[hidden]:",
		"<!-- important: after",
		"<!-- note: also read",
		"<!-- when using any",
		"tool description:",
		"tool_description:",
	]
	pattern := patterns[_]
	contains(lower(input.content), pattern)
	msg := sprintf("possible MCP/tool poisoning pattern: %q", [pattern])
}
