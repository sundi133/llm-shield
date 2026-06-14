"""MCP proxy: in-process enforcement core + transport scaffold.

``enforcement`` holds the reusable, offline-testable decision logic; the
transport server (proxy_server) is a thin shell that delegates to it.
"""
