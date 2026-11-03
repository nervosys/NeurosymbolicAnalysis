"""Stands in for the model: the remote entry point its output comes from."""

from flask import request


def command():
    return request.args["command"]
