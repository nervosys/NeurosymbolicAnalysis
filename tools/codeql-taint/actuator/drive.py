"""The effector: where output leaves the system."""

import os


def write_actuator(value):
    os.system("actuator " + value)
