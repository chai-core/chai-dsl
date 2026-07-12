import ChaiProofs.Emission

/-!
# DRT oracle: the executable Lean emission state machine

Companion to `DrtOracle.lean`, for the emission layer. Reads one effect stream per
stdin line and prints the action stream `steps` produces from the initial (live,
empty-buffer) state. Lets the Rust `EmissionEnforcer` be differentially tested
against the *proven* emission model.

Line format: whitespace-separated effect names from
`allow downgrade redact defer requireHuman deny`.
Output: the space-separated action stream (`emit buffer redact drop requireHuman`).
-/

open ChaiProofs

def effOfStr : String → Option Effect
  | "allow" => some Effect.allow
  | "downgrade" => some Effect.downgrade
  | "redact" => some Effect.redact
  | "defer" => some Effect.defer
  | "requireHuman" => some Effect.requireHuman
  | "deny" => some Effect.deny
  | _ => none

def actStr : Action → String
  | Action.emit => "emit"
  | Action.buffer => "buffer"
  | Action.redact => "redact"
  | Action.drop => "drop"
  | Action.requireHuman => "requireHuman"

def parseEffs (line : String) : Option (List Effect) :=
  let toks := (line.splitOn " ").filter (· ≠ "")
  toks.foldr (fun t acc =>
    match acc, effOfStr t with
    | some xs, some e => some (e :: xs)
    | _, _ => none) (some [])

partial def loop (h : IO.FS.Stream) : IO Unit := do
  let line ← h.getLine
  if line == "" then
    pure ()
  else
    let l := (line.replace "\n" "").replace "\r" ""
    if l ≠ "" then
      match parseEffs l with
      | some effs =>
        let acts := (steps { buffered := false, halted := false } effs).1
        IO.println (" ".intercalate (acts.map actStr))
      | none => IO.println "PARSE_ERROR"
    loop h

def main : IO Unit := do
  loop (← IO.getStdin)
