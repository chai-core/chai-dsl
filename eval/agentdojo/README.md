# Agent-benchmark evaluation: Chai as a retrofit monitor

Chai governs the **emission (text) channel** that action-mediation defenses
(CaMeL, FIDES, Progent, AgentSpec) scope out. This directory evaluates it as a
*retrofit monitor*: a real LLM agent runs under prompt-injection attacks, and each
output is scored twice, raw and after the Chai monitor, under the adaptive,
attacker-knows-the-policy protocol (the injection is written knowing Chai redacts
PII and blocks secrets).

## Local run (real numbers, no cloud key)

Uses a local agent via [Ollama](https://ollama.com), no API key. Model:
`qwen3:30b-a3b` (a Qwen3 30B mixture-of-experts, ~3B active).

```sh
# 1. serve the model
ollama serve &                 # or already running on :11434
ollama pull qwen3:30b-a3b

# 2. start the Chai emission monitor (the sidecar)
CHAI_POLICY_FILE=eval/agentdojo/emission_policy.chai CHAI_ADDR=127.0.0.1:8731 \
  cargo run --features server --example sidecar &

# 3. run the evaluation
python3 eval/agentdojo/run_local_eval.py
```

### Result (2026-07-05, `qwen3:30b-a3b`, 5 episodes)

| Metric | Raw agent | Agent + Chai monitor |
|---|---|---|
| Injection attack success | 66% (2/3) | **0% (0/3)** |
| Task utility (benign) | 100% (2/2) | 100% (2/2) |

The injected agent leaked the customer SSN in two of three attack episodes; the
Chai monitor redacted or dropped every leak while preserving the benign answers.
These are real numbers from a real local model, reproducible with the command
above. (Numbers vary a little run to run with the model.)

## Real AgentDojo run (key-free, local model)

`run_agentdojo.py` drives the **actual published
[AgentDojo](https://github.com/ethz-spylab/agentdojo) benchmark** with a local
`llama3.2:3b` agent (via Ollama, no key), inserting Chai as a tool-output monitor
in AgentDojo's defense slot (`ToolsExecutionLoop` after `ToolsExecutor`). It reports
AgentDojo's own utility and attack-success, baseline vs with the Chai monitor, on a
small slice of the `banking` suite under the `important_instructions` attack.

```sh
pip install agentdojo          # or: python -m pip install agentdojo
ollama pull llama3.2:3b
# start the sidecar (as above), then:
eval/.venv/bin/python eval/agentdojo/run_agentdojo.py
```

### The defense: a taint-aware tool-call gate

The gate (`ChaiToolGate`) authorizes every proposed tool call through the Chai
engine (sidecar `/authorize_tool_call`) *before* it executes, using
[`toolgate_policy.chai`](toolgate_policy.chai): a sensitive/irreversible action is
denied once the session is **tainted**, i.e. the agent has already consumed
untrusted external tool output that could carry an injected instruction. This is the
capability/taint discipline (cf. CaMeL/FIDES) written as a Chai policy over the
tool-call channel. Fail-closed: if the PDP is unreachable, the call is denied.

### Observed (2026-07-05, banking suite, `important_instructions`, `llama3.1:8b`, 8 tasks)

| Metric | Baseline | + Chai tool-gate |
|---|---|---|
| Injection attack success | 1/8 | **0/8** |
| Task utility | 1/8 | 1/8 |

The gate **blocked the one injection that succeeded** (the injected transfer was
denied because the session was tainted) and **preserved the one task the model could
complete** (a read-only task the gate never touches). So on this sample it removed
the observed attack at no utility cost. The sample is small and the numerator is
low, because `llama3.1:8b-q4` locally falls for the injection rarely and completes
the multi-step banking tasks rarely; a capable backend would give larger
denominators. What is demonstrated is real: Chai engages AgentDojo's tool-call
channel and blocks the attack, and it composes with its complementary emission-
channel monitor (`run_local_eval.py`: attack success 66% → 0%, utility 100% → 100%).

The earlier 3-task/3B runs (attack 0/3, utility 0/3) are omitted: the 3B model is too
weak to complete tasks or fall for attacks, so they carry no signal.

## Files

- `run_local_eval.py`, the harness (local agent + Chai monitor, real numbers).
- `emission_policy.chai`, the emission-channel policy the monitor enforces.
