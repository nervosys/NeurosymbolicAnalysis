"""The effector. `write_actuator` is the taint sink."""


def write_actuator(value):
    print(f"actuator <- {value}")
