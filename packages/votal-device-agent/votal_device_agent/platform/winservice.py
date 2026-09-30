"""The Windows service host. The Service Control Manager expects a service to
report that it started and to answer stop requests; a plain executable is
killed after 30 seconds. pywin32 provides that protocol (Windows only)."""

from __future__ import annotations

import threading

import servicemanager  # type: ignore
import win32event  # type: ignore
import win32service  # type: ignore
import win32serviceutil  # type: ignore

NAME = "VotalDeviceAgent"


class VotalDeviceAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = NAME
    _svc_display_name_ = "Votal Device Agent"
    _svc_description_ = "Checks prompts to AI tools on this computer against your company's policy."

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = threading.Event()
        self.wait_handle = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.stop_event.set()
        win32event.SetEvent(self.wait_handle)

    def SvcDoRun(self):
        from votal_device_agent.installed import run_installed
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        run_installed("windows", stop=self.stop_event)


def dispatch() -> int:
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(VotalDeviceAgentService)
    servicemanager.StartServiceCtrlDispatcher()
    return 0
