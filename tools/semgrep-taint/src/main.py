import sys

sys.path[:0] = ["models/policy", "src/guard", "src/telemetry", "src/actuator"]

from clamp import clamp
from drive import write_actuator
from infer import infer
from relay import relay


def guarded(prompt):
    """The intended path: everything the model produces is clamped first."""
    raw = infer(prompt)
    settled = raw
    checked = clamp(settled["command"])
    write_actuator(checked)


def bypass(prompt):
    """The path the architecture declaration forgot."""
    raw = infer(prompt)
    settled = raw
    forwarded = relay(settled)
    write_actuator(forwarded)
