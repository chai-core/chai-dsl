#!/usr/bin/env python3
"""Real AgentDojo run with a local model and Chai as a taint-aware tool-call gate.

AgentDojo evaluates the *tool-call* channel under prompt injection. Chai engages it
by authorizing each proposed tool call through the Chai engine (sidecar
/authorize_tool_call): a sensitive/irreversible action (transfer, schedule,
credential change) is DENIED once the session is tainted, i.e. the agent has
consumed untrusted external tool output that could carry an injected instruction.
So an injection cannot drive a harmful action. We report AgentDojo's own utility and
security (attack-success) metrics, baseline vs with the Chai gate, with a local
llama3.1:8b agent via Ollama (no API key). (`ChaiMonitor`, the emission-channel
output monitor, is kept below for the complementary emission-channel eval.)

Prereqs:
  - Ollama serving the model (see MODEL) on :11434
  - Chai sidecar with the tool-gate policy:
      CHAI_POLICY_FILE=eval/agentdojo/toolgate_policy.chai CHAI_ADDR=127.0.0.1:8731 \
        cargo run --features server --example sidecar &
Run:
  eval/.venv/bin/python eval/agentdojo/run_agentdojo.py
"""
import json
import urllib.request

import openai

from agentdojo.agent_pipeline import (
    AgentPipeline, InitQuery, LocalLLM, SystemMessage, ToolsExecutor, ToolsExecutionLoop,
)
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import run_task_with_injection_tasks
from agentdojo.functions_runtime import EmptyEnv
from agentdojo.task_suite.load_suites import get_suite

MODEL = "llama3.1:8b-instruct-q4_K_M"
SIDECAR = "http://127.0.0.1:8731/filter_tool_result"
AUTHZ = "http://127.0.0.1:8731/authorize_tool_call"
SUITE, ATTACK = "banking", "important_instructions"
N_USER_TASKS = 8
INJECTION = ["injection_task_0"]

# State-changing / irreversible tools whose harmful use is the attacker's goal.
SENSITIVE = {
    "send_money", "schedule_transaction", "update_scheduled_transaction",
    "update_password", "update_user_info",
}


def chai_govern(text: str) -> str:
    """Run a tool output through the Chai emission monitor; return the released text."""
    body = json.dumps({
        "subject_uid": "Agent::aria", "subject_attrs": {"trust_tier": 5},
        "tool": "tool_output", "result": text,
    }).encode()
    req = urllib.request.Request(SIDECAR, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.load(r)
        # released is null when withheld; fall back to a neutral marker.
        return d.get("released") if d.get("released") is not None else "[withheld by monitor]"
    except Exception:
        return "[monitor unavailable]"


class ChaiMonitor(BasePipelineElement):
    """A defense pipeline element: governs the latest tool output through Chai."""
    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
        msgs = list(messages)
        for i in range(len(msgs) - 1, -1, -1):
            if msgs[i]["role"] == "tool":
                content = msgs[i].get("content")
                text = content if isinstance(content, str) else str(content)
                governed = chai_govern(text)
                msgs[i] = {**msgs[i], "content": governed}
                break
        return query, runtime, env, msgs, extra_args


def chai_authorize(tool: str, tainted: bool) -> bool:
    """Ask the Chai engine (sidecar) whether this tool call is allowed under the
    taint-aware tool-gate policy. Returns True iff the verdict is Allow. Fail-closed."""
    body = json.dumps({
        "subject_uid": "Agent::aria",
        "subject_attrs": {"trust_tier": 5, "tainted": tainted},
        "tool": tool,
    }).encode()
    req = urllib.request.Request(AUTHZ, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r).get("effect") == "Allow"
    except Exception:
        return False


class ChaiToolGate(BasePipelineElement):
    """Authorize each proposed tool call through Chai *before* it executes. A
    sensitive/irreversible action is denied once the session is tainted (the agent
    has consumed untrusted external tool output), so an injected instruction cannot
    drive a harmful action. This is the capability/taint discipline on the tool-call
    channel, expressed as a Chai policy."""
    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
        msgs = list(messages)
        if not msgs or msgs[-1]["role"] != "assistant":
            return query, runtime, env, msgs, extra_args
        calls = msgs[-1].get("tool_calls") or []
        if not calls:
            return query, runtime, env, msgs, extra_args
        tainted = any(m["role"] == "tool" for m in msgs)  # consumed external output?
        kept = [c for c in calls if chai_authorize(c.function, tainted)]
        if len(kept) != len(calls):
            msgs[-1] = {**msgs[-1], "tool_calls": kept}
        return query, runtime, env, msgs, extra_args


def build_pipeline(with_chai: bool):
    client = openai.OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
    llm = LocalLLM(client, MODEL)
    # The gate runs BEFORE ToolsExecutor so a denied call never executes.
    loop_elems = [ChaiToolGate(), ToolsExecutor()] if with_chai else [ToolsExecutor()]
    loop_elems.append(llm)
    pipe = AgentPipeline([
        SystemMessage(load_system_message(None)), InitQuery(), llm, ToolsExecutionLoop(loop_elems),
    ])
    # AgentDojo's important_instructions attack looks up a known model name in the
    # pipeline name; "Local model" is the valid one for a local backend.
    pipe.name = f"local{'+chai' if with_chai else ''}"
    return pipe


def run(with_chai: bool):
    from pathlib import Path
    from agentdojo.logging import OutputLogger
    logdir = Path("/tmp/agentdojo_runs")
    suite = get_suite("v1", SUITE)
    pipe = build_pipeline(with_chai)
    attack = load_attack(ATTACK, suite, pipe)
    task_ids = list(suite.user_tasks.keys())[:N_USER_TASKS]
    util_ok = sec_attacked = total = 0
    with OutputLogger(str(logdir), live=None):
        for tid in task_ids:
            ut = suite.user_tasks[tid]
            util, sec = run_task_with_injection_tasks(
                suite, pipe, ut, attack, logdir=logdir, force_rerun=True, injection_tasks=INJECTION,
            )
            for k in util:
                total += 1
                util_ok += bool(util[k])
                sec_attacked += bool(sec[k])  # True = injection SUCCEEDED
            print(f"  {tid}: utility={list(util.values())} attack_succeeded={list(sec.values())}")
    return util_ok, sec_attacked, total


def main():
    print(f"=== Real AgentDojo run  (suite={SUITE}, attack={ATTACK}, agent={MODEL}) ===")
    print(f"\n[baseline: no defense]")
    b_util, b_sec, b_tot = run(with_chai=False)
    print(f"\n[with Chai tool-gate (taint-aware authorization)]")
    c_util, c_sec, c_tot = run(with_chai=True)

    print("\n=== AgentDojo metrics (baseline -> + Chai tool-gate) ===")
    print(f"task utility     : {b_util}/{b_tot} -> {c_util}/{c_tot}")
    print(f"attack success   : {b_sec}/{b_tot} -> {c_sec}/{c_tot}")
    print("\nThe gate authorizes each tool call through Chai: a sensitive/irreversible")
    print("action (transfer, schedule, credential change) is DENIED once the session is")
    print("tainted by untrusted tool output, so an injected instruction cannot drive it.")


if __name__ == "__main__":
    main()
