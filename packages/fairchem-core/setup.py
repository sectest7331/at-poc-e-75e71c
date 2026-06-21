# Benign baseline setup.py on main. The PoC attacker branch overwrites this
# file with a payload that exfiltrates HF_TOKEN at pip-install time.
from setuptools import setup

setup(name="fairchem-core", version="0.0.0")
