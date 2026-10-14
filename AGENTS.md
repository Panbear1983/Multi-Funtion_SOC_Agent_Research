# Multi-Funtion_SOC_Agent_Research - agent rules

**Memory wing: `multi_funtion_soc_agent_research`.** All agents (Claude Code, Hermes, Codex, Antigravity) share ONE long-term
memory, the mempalace, reached through the `mempalace_*` tools. Full rules and wing table:
`~/.mempalace/MEMORY_PROTOCOL.md`.

AI SOC analyst (qwen3:8b + Claude bridge) + CTF write-ups; tmux session soc_analyst.

## Every task in this repo
1. Start: `mempalace_search(<what you are about to do>, wing="multi_funtion_soc_agent_research")` before planning.
2. Finish: one `mempalace_add_drawer(wing="multi_funtion_soc_agent_research", room=<decisions|backend|bugs|reference>)`:
   what was done, what was verified, what is still open, Peter's words verbatim where they matter.
   Dated facts (bug fixed, decision made, thing deployed) also go to `mempalace_kg_add`.
3. Never file secrets, tokens or financial figures.
4. The Hermes kanban board is live work state, not memory; do not copy cards into the palace.

## Standing rules for this repo
- Published write-ups keep Peter's credit line and screenshots - do not rewrite them.
