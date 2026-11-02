"""Read-only local hardware inventory, separate from actual engine device usage."""
from __future__ import annotations

import csv
import ctypes
import importlib.metadata
import io
import json
import os
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from functools import lru_cache
from backend.system.device import training_device


@lru_cache(maxsize=1)
def cpu_name() -> str:
    if os.name == "nt":
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
                return str(winreg.QueryValueEx(key, "ProcessorNameString")[0]).strip()
        except OSError:
            pass
    return platform.processor() or "Unknown processor"


def memory_info() -> dict:
    if os.name == "nt":
        class MemoryStatus(ctypes.Structure):
            _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong)] + [
                (key, ctypes.c_ulonglong) for key in
                ("total", "available", "total_page", "available_page", "total_virtual", "available_virtual", "extended")]
        status = MemoryStatus()
        status.length = ctypes.sizeof(status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return {"total_bytes": status.total, "available_bytes": status.available}
    try:
        page = os.sysconf("SC_PAGE_SIZE")
        return {"total_bytes": page * os.sysconf("SC_PHYS_PAGES"),
                "available_bytes": page * os.sysconf("SC_AVPHYS_PAGES")}
    except (AttributeError, OSError, ValueError):
        return {"total_bytes": 0, "available_bytes": 0}


def query(command: list[str]) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=4,
                                encoding="utf-8", errors="replace",
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return result.stdout.strip() if result.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


@lru_cache(maxsize=1)
def detect_gpus() -> list[dict]:
    gpus = []
    nvidia = shutil.which("nvidia-smi")
    if nvidia:
        output = query([nvidia, "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader,nounits"])
        for row in csv.reader(io.StringIO(output)):
            if len(row) == 3:
                try:
                    memory = int(float(row[1].strip()) * 1024**2)
                except ValueError:
                    memory = None
                gpus.append({"name": row[0].strip(), "memory_bytes": memory, "driver": row[2].strip(), "source": "nvidia-smi"})
    if os.name == "nt":
        output = query(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
                        "Get-CimInstance Win32_VideoController | Select-Object Name,DriverVersion | ConvertTo-Json -Compress"])
        try:
            adapters = json.loads(output)
            if isinstance(adapters, dict):
                adapters = [adapters]
            for adapter in adapters:
                name = adapter.get("Name")
                if name and not any(gpu["name"].lower() == name.lower() for gpu in gpus):
                    gpus.append({"name": name, "memory_bytes": None, "driver": adapter.get("DriverVersion"), "source": "Windows"})
        except (ValueError, TypeError):
            pass
    return gpus


def package_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def get_system_info() -> dict:
    device = training_device()
    return {
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "cpu": {"name": cpu_name(), "logical_cores": os.cpu_count() or 1},
        "memory": memory_info(),
        "gpus": detect_gpus(),
        "runtime": {"os": platform.platform(), "architecture": platform.machine(),
                    "python": platform.python_version(), "numpy": package_version("numpy"), "torch": package_version("torch")},
        "training": {"device": device, "gpu_in_use": device.startswith("cuda"),
                     "note": "新实验自动使用可用的 NVIDIA GPU。" if device.startswith("cuda") else
                             "CUDA 不可用，新实验自动使用本机 CPU。"},
    }
