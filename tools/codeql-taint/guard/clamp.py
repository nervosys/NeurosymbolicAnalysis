"""The guard the architecture declaration claims is always crossed."""


def clamp(value):
    return value if value in {"status", "stop", "start"} else "status"
