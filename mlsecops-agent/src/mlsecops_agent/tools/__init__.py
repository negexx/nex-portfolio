"""Subprocess wrappers around external security CLIs.

Every wrapper validates the tool's stdout/JSON via Pydantic. Tool absence
returns a sentinel; tool malformed output raises ToolError.
"""
