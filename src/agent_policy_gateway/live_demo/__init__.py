"""Agent Policy Gateway Live Demo — Real AI agent + real database through the gateway.

Demonstrates Agent Policy Gateway enforcing policy on actual LLM-generated actions:
- Agent tries to query data → ALLOWED (SELECT in policy)
- Agent tries to delete data → DENIED (DELETE not in policy)
- Agent tries to access internal metadata → DENIED (egress control)
- Agent tries to exfiltrate data → DENIED (response filtering)

The LLM provider is swappable: Ollama, OpenAI, Anthropic, etc.
"""
