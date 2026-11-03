"""One guarded path and one bypass, crossing component boundaries."""

from flask import Flask

from actuator.drive import write_actuator
from guard.clamp import clamp
from policy.serve import command
from telemetry.relay import relay

app = Flask(__name__)


@app.route("/guarded")
def guarded():
    raw = command()
    write_actuator(clamp(raw))
    return "ok"


@app.route("/bypass")
def bypass():
    raw = command()
    write_actuator(relay(raw))
    return "ok"
