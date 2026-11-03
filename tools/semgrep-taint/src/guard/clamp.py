"""The shield. `clamp` is the sanitizer."""

LIMIT = 100


def clamp(command):
    return max(-LIMIT, min(LIMIT, int(command)))
