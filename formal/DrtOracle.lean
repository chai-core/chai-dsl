import ChaiProofs.Decision

/-!
# DRT oracle: the executable Lean decision model

This makes the *proven* Lean decision model runnable so the Rust engine can be
differentially tested against it directly (cedar-drt style), instead of against a
Rust transcription of it. It reads one case per stdin line and prints the model's
verdict per line.

Line format: whitespace-separated outcome tokens.
  `U`            an unmatched rule
  `M:<effect>`   a matched rule with the given effect
  `E:<effect>`   a rule whose guard errored, tagged with its effect
where `<effect>` is one of `allow downgrade redact defer requireHuman deny`.
Output: the decision effect for that case (or `PARSE_ERROR`).
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

def strOfEff : Effect → String
  | Effect.allow => "allow"
  | Effect.downgrade => "downgrade"
  | Effect.redact => "redact"
  | Effect.defer => "defer"
  | Effect.requireHuman => "requireHuman"
  | Effect.deny => "deny"

def parseTok (t : String) : Option Outcome :=
  match t.splitOn ":" with
  | ["U"] => some Outcome.unmatched
  | ["M", e] => (effOfStr e).map Outcome.matched
  | ["E", e] => (effOfStr e).map Outcome.errored
  | _ => none

def parseLine (line : String) : Option (List Outcome) :=
  let toks := (line.splitOn " ").filter (· ≠ "")
  toks.foldr (fun t acc =>
    match acc, parseTok t with
    | some xs, some o => some (o :: xs)
    | _, _ => none) (some [])

partial def loop (h : IO.FS.Stream) : IO Unit := do
  let line ← h.getLine
  if line == "" then
    pure ()
  else
    let l := (line.replace "\n" "").replace "\r" ""
    if l ≠ "" then
      match parseLine l with
      | some outs => IO.println (strOfEff (decision outs))
      | none => IO.println "PARSE_ERROR"
    loop h

def main : IO Unit := do
  loop (← IO.getStdin)
