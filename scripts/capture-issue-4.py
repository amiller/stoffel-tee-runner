#!/usr/bin/env python3
"""Capture .evidence/issue-4/ screenshots against the mock (issue #4).

Drives the real snap firefox headless via geckodriver (W3C WebDriver). The
CDP/automation-detection concern does not apply: this is our own page on
loopback. Every step asserts the DOM condition it screenshots, so a blank or
stale capture cannot pass.
"""
import base64
import json
import subprocess
import sys
import time
import urllib.request

PAGE = "http://127.0.0.1:8081"
OUT = ".evidence/issue-4"
WD = "http://127.0.0.1:4444"
JOB = "f00dfeedf00dfeedf00dfeedf00dfeedf00dfeedf00dfeedf00dfeedf00dfeed"


def wd(method, path, body=None):
    req = urllib.request.Request(
        WD + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read() or b"{}")["value"]


def wait_for(fn, what, timeout=30):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = fn()
            if last:
                return last
        except Exception as e:  # element not found yet — keep waiting
            last = e
        time.sleep(0.3)
    raise SystemExit(f"timed out waiting for {what}: {last}")


def text(css):
    def get():
        el = wd("POST", f"/session/{SID}/element",
                {"using": "css selector", "value": css})
        return wd("GET", f"/session/{SID}/element/{el['element-6066-11e4-a52e-4f735466cecf']}/text")
    return get


def scroll(css):
    wd("POST", f"/session/{SID}/execute/sync",
       {"script": f"document.querySelector('{css}').scrollIntoView()",
        "args": []})
    time.sleep(0.5)


def shot(name):
    png = base64.b64decode(wd("GET", f"/session/{SID}/screenshot"))
    path = f"{OUT}/{name}"
    with open(path, "wb") as f:
        f.write(png)
    if len(png) < 5000:
        raise SystemExit(f"{path} is suspiciously small ({len(png)} B)")
    print(f"wrote {path} ({len(png)} B)")


drv = subprocess.Popen(["geckodriver", "--port", "4444"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    time.sleep(1)
    SID = wd("POST", "/session", {"capabilities": {"alwaysMatch": {
        "moz:firefoxOptions": {"args": ["-headless"]}}}})["sessionId"]
    wd("POST", f"/session/{SID}/window/rect", {"width": 1280, "height": 1000})

    wd("POST", f"/session/{SID}/url", {"url": f"{PAGE}/"})
    href = wd("GET", f"/session/{SID}/url")
    assert href == f"{PAGE}/", f"navigation failed: {href}"
    wait_for(text("#nodes table tr td"), "nodes table rows")
    print("nodes rows:", text("#nodes table")()[:120].replace("\n", " | "))
    wait_for(lambda: "quote sha256 " in text("#nodes")(), "quote fingerprints")
    shot("01-nodes.png")

    wait_for(lambda: "UNCONSTRAINED" in text("#jobs")(), "unconstrained warning")
    states = [l for l in text("#jobs")().split("\n") if l and l[-1] == ")"]
    print("job groups:", states)
    scroll("#jobs-view")
    shot("02-jobs.png")

    wd("POST", f"/session/{SID}/url", {"url": f"{PAGE}/#job={JOB}"})
    href = wd("GET", f"/session/{SID}/url")
    assert href == f"{PAGE}/#job={JOB}", f"navigation failed: {href}"
    cmd = wait_for(lambda: t if (t := text(".command code")()).startswith("stoffel-verify") else None,
                   "command box")
    print("command shown:", cmd)
    at = int(cmd.split("--at ")[1].split()[0])
    assert at == 1751624163, f"pinned --at is {at}, expected the window midpoint 1751624163"
    wait_for(lambda: "Bundle JSON as served" in text("#evidence")(), "bundle JSON view")
    scroll("#evidence-view")
    values = [l for l in text("#evidence .summary")().split("\n")]
    print("summary:", " | ".join(values[:10]))
    shot("03-evidence-tampered.png")

    with open(f"{OUT}/command-shown.txt", "w") as f:
        f.write(cmd + "\n")
    wd("DELETE", f"/session/{SID}")
finally:
    drv.terminate()
