#!/usr/bin/env python3
"""Render an agent run trace into a readable transcript: every step of the loop - the agent's narration,
its reasoning, each tool call with arguments, what each tool returned, file edits, and the final outcome.
Handles both Claude (stream-json) and Codex (--json). usage: render-transcript.py <trace.jsonl>"""
import json, sys

def trunc(s, n=700):
    s = s if isinstance(s, str) else json.dumps(s)
    s = s.replace("\r", "")
    return s if len(s) <= n else s[:n] + f"  …(+{len(s)-n} more chars)"
def tool_args(inp):
    if not isinstance(inp, dict): return trunc(inp, 160)
    return ", ".join(f"{k}={trunc(v if isinstance(v,str) else json.dumps(v),140)}" for k, v in inp.items())

def _loads(line):
    try: return json.loads(line)
    except json.JSONDecodeError: return None  # skip non-JSON noise (e.g. java image's Maven warning on stdout)
events = [e for e in (_loads(l) for l in open(sys.argv[1]) if l.strip()) if e is not None]
is_codex = any(e.get("type", "").startswith(("item.", "turn.", "thread.")) for e in events)
out = []

if is_codex:
    usage = None
    for e in events:
        t = e.get("type")
        if t == "item.completed":
            it = e.get("item", {}); k = it.get("type")
            if k == "agent_message":
                out.append(f"**Codex:** {it.get('text','')}\n")
            elif k == "command_execution":
                out.append(f"**→ shell:** `{trunc(it.get('command',''),200)}`")
                if it.get("aggregated_output"):
                    out.append(f"```\n{trunc(it['aggregated_output'],500)}\n```")
            elif k == "file_change":
                out.append("**✎ files:** " + ", ".join(f"{c.get('kind')} `{c.get('path')}`" for c in it.get("changes", [])) + "\n")
        elif t == "turn.completed":
            usage = e.get("usage")
    if usage:
        out.append(f"\n---\n*tokens — input {usage.get('input_tokens')} (cached {usage.get('cached_input_tokens')}), output {usage.get('output_tokens')}, reasoning {usage.get('reasoning_output_tokens')}*")
else:  # Claude stream-json
    for e in events:
        t = e.get("type")
        if t == "assistant":
            for b in e.get("message", {}).get("content", []):
                bt = b.get("type")
                if bt == "text" and b.get("text", "").strip():
                    out.append(f"**Claude:** {b['text']}\n")
                elif bt == "thinking" and b.get("thinking", "").strip():
                    out.append(f"> *thinking:* {trunc(b['thinking'],900)}\n")
                elif bt == "tool_use":
                    out.append(f"**→ {b.get('name')}**({tool_args(b.get('input'))})")
        elif t == "user":
            c = e.get("message", {}).get("content", [])
            for b in (c if isinstance(c, list) else []):
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    cont = b.get("content", "")
                    if isinstance(cont, list):
                        cont = " ".join(x.get("text", "") for x in cont if isinstance(x, dict))
                    out.append(f"  ↳ *result:* {trunc(cont,350)}")
        elif t == "result":
            out.append(f"\n---\n**Final ({e.get('subtype')}):** {e.get('result','')}")
            out.append(f"\n*turns {e.get('num_turns')} · cost ${round(e.get('total_cost_usd') or 0,3)}*")
print("\n".join(out))
