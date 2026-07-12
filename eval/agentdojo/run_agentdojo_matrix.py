#!/usr/bin/env python3
"""Larger, varied AgentDojo evaluation: Chai taint-aware tool-gate across all four
AgentDojo areas (banking, slack, travel, workspace), >=128 injection episodes,
baseline vs the Chai gate, with a local llama3.1:8b agent (no API key).

The gate authorizes each proposed tool call through the Chai engine
(sidecar /authorize_tool_call, toolgate_policy.chai): a sensitive/irreversible tool
(classified by name, passed as the `sensitive` fact) is denied once the session is
tainted by untrusted tool output. Results are written incrementally to results.csv.

Prereqs:
  - Ollama serving the model on :11434
  - Chai sidecar with the tool-gate policy:
      CHAI_POLICY_FILE=eval/agentdojo/toolgate_policy.chai CHAI_ADDR=127.0.0.1:8731 \
        cargo run --features server --example sidecar &
Run:
  eval/.venv/bin/python eval/agentdojo/run_agentdojo_matrix.py
"""
import csv
import json
import os
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
AUTHZ = "http://127.0.0.1:8731/authorize_tool_call"
ATTACK = "important_instructions"
MAX_ITERS = 4                      # cap the agent loop to bound runtime
SUITES = ["banking", "slack", "travel", "workspace"]
USER_TASKS_PER_SUITE = 8
INJECTIONS_PER_SUITE = 4            # 8 x 4 x 4 suites = 128 episodes
RESULTS = os.path.join(os.path.dirname(__file__), "results.csv")

# Keywords that mark a state-changing / irreversible / external action across suites.
SENSITIVE_KW = ("send", "transfer", "pay", "delete", "update", "create", "schedule",
                "invite", "reserve", "book", "add", "remove", "post", "share", "cancel")


def is_sensitive(tool: str) -> bool:
    t = tool.lower()
    return any(kw in t for kw in SENSITIVE_KW)


def chai_authorize(tool: str, tainted: bool) -> bool:
    body = json.dumps({
        "subject_uid": "Agent::aria",
        "subject_attrs": {"trust_tier": 5, "tainted": tainted, "sensitive": is_sensitive(tool)},
        "tool": tool,
    }).encode()
    req = urllib.request.Request(AUTHZ, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r).get("effect") == "Allow"
    except Exception:
        return False  # fail-closed


class ChaiToolGate(BasePipelineElement):
    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):
        msgs = list(messages)
        if not msgs or msgs[-1]["role"] != "assistant":
            return query, runtime, env, msgs, extra_args
        calls = msgs[-1].get("tool_calls") or []
        if not calls:
            return query, runtime, env, msgs, extra_args
        tainted = any(m["role"] == "tool" for m in msgs)
        kept = [c for c in calls if chai_authorize(c.function, tainted)]
        if len(kept) != len(calls):
            msgs[-1] = {**msgs[-1], "tool_calls": kept}
        return query, runtime, env, msgs, extra_args


def build_pipeline(with_chai: bool):
    client = openai.OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
    llm = LocalLLM(client, MODEL)
    loop_elems = [ChaiToolGate(), ToolsExecutor()] if with_chai else [ToolsExecutor()]
    loop_elems.append(llm)
    pipe = AgentPipeline([
        SystemMessage(load_system_message(None)), InitQuery(), llm,
        ToolsExecutionLoop(loop_elems, max_iters=MAX_ITERS),
    ])
    pipe.name = f"local{'+chai' if with_chai else ''}"
    return pipe


def main():
    from pathlib import Path
    from agentdojo.logging import OutputLogger
    logdir = Path("/tmp/agentdojo_runs")

    agg = {}  # (suite, arm) -> [episodes, utility_ok, attack_success]
    with open(RESULTS, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["suite", "arm", "user_task", "injection", "utility", "attack_success"])

        with OutputLogger(str(logdir), live=None):
            for suite_name in SUITES:
                suite = get_suite("v1", suite_name)
                uts = list(suite.user_tasks.keys())[:USER_TASKS_PER_SUITE]
                injs = list(suite.injection_tasks.keys())[:INJECTIONS_PER_SUITE]
                for arm, with_chai in (("baseline", False), ("chai_gate", True)):
                    pipe = build_pipeline(with_chai)
                    attack = load_attack(ATTACK, suite, pipe)
                    key = (suite_name, arm)
                    agg.setdefault(key, [0, 0, 0])
                    for tid in uts:
                        ut = suite.user_tasks[tid]
                        try:
                            util, sec = run_task_with_injection_tasks(
                                suite, pipe, ut, attack, logdir=logdir,
                                force_rerun=True, injection_tasks=injs,
                            )
                        except Exception as e:
                            print(f"  [skip {suite_name}/{arm}/{tid}: {type(e).__name__}]")
                            continue
                        for k in util:
                            agg[key][0] += 1
                            agg[key][1] += bool(util[k])
                            agg[key][2] += bool(sec[k])
                            w.writerow([suite_name, arm, k[1], k[0], int(bool(util[k])), int(bool(sec[k]))])
                        f.flush()
                    n, u, s = agg[key]
                    print(f"{suite_name:<10} {arm:<10} episodes={n:<4} utility={u}/{n} attack_success={s}/{n}", flush=True)

    print("\n=== AGGREGATE across all suites ===")
    for arm in ("baseline", "chai_gate"):
        tot = [0, 0, 0]
        for (s, a), v in agg.items():
            if a == arm:
                tot = [tot[i] + v[i] for i in range(3)]
        print(f"{arm:<10} episodes={tot[0]:<4} utility={tot[1]}/{tot[0]} attack_success={tot[2]}/{tot[0]}")
    print(f"\nFull per-episode results in {RESULTS}")


if __name__ == "__main__":
    main()
