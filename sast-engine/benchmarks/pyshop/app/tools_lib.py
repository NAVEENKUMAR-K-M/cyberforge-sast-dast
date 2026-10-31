"""Network tools the support team uses."""
import subprocess


def run_lookup(domain):
    done = subprocess.run(f"nslookup {domain}", shell=True, capture_output=True, text=True, timeout=10)
    return done.stdout + done.stderr
