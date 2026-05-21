from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = ROOT_DIR / "ctf_app" / "gui" / "frontend"
REQUIREMENTS_FILE = ROOT_DIR / "requirements.txt"
VENV_DIR = ROOT_DIR / ".venv"
VENV_PYTHON = VENV_DIR / "Scripts" / "python.exe" if os.name == "nt" else VENV_DIR / "bin" / "python"
NODE_MODULES_DIR = FRONTEND_DIR / "node_modules"
NPM_CMD = "npm.cmd" if os.name == "nt" else "npm"


def run_command(cmd: list[str], *, python_exe: Path | None = None) -> int:
    if python_exe is not None:
        cmd = [str(python_exe), *cmd]
    return subprocess.run(cmd, cwd=str(ROOT_DIR), check=False).returncode


def in_project_venv() -> bool:
    return Path(sys.executable).resolve() == VENV_PYTHON.resolve() if VENV_PYTHON.exists() else False


def ensure_venv() -> int:
    if VENV_PYTHON.exists():
        return 0
    print("[bootstrap] Creating .venv ...")
    return subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], cwd=str(ROOT_DIR), check=False).returncode


def install_runtime(*, python_exe: Path | None = None) -> int:
    target_python = python_exe or Path(sys.executable)
    code = run_command(["-m", "pip", "install", "-U", "pip", "setuptools", "wheel"], python_exe=target_python)
    if code != 0:
        return code
    code = run_command(["-m", "pip", "install", "-r", str(REQUIREMENTS_FILE)], python_exe=target_python)
    if code != 0:
        return code
    return run_command(
        ["-m", "pip", "install", "-U", "yt-dlp", "yt-dlp-ejs", "imageio-ffmpeg", "curl_cffi"],
        python_exe=target_python,
    )


def ensure_frontend_runtime() -> int:
    if NODE_MODULES_DIR.exists():
        return 0
    print("[bootstrap] Installing frontend dependencies ...")
    return subprocess.run([NPM_CMD, "install"], cwd=str(FRONTEND_DIR), check=False).returncode


def reexec_in_venv(argv: list[str]) -> int:
    return subprocess.run([str(VENV_PYTHON), str(ROOT_DIR / "start.py"), *argv], cwd=str(ROOT_DIR), check=False).returncode


def wait_for_port(port: int, *, host: str = "127.0.0.1", timeout_s: float = 20.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.4)
    return False


def launch_web(*, api_port: int, web_port: int) -> int:
    code = ensure_frontend_runtime()
    if code != 0:
        return code

    api_proc = subprocess.Popen(
        [
            str(VENV_PYTHON),
            "-m",
            "uvicorn",
            "ctf_app.web.api:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(api_port),
        ],
        cwd=str(ROOT_DIR),
    )
    if not wait_for_port(api_port):
        api_proc.terminate()
        return 1

    env = os.environ.copy()
    env["BROWSER"] = "none"
    web_proc = subprocess.Popen(
        [NPM_CMD, "run", "dev", "--", "--host", "127.0.0.1", "--port", str(web_port)],
        cwd=str(FRONTEND_DIR),
        env=env,
    )
    if not wait_for_port(web_port):
        web_proc.terminate()
        api_proc.terminate()
        return 1

    webbrowser.open(f"http://127.0.0.1:{web_port}")

    try:
        return web_proc.wait()
    finally:
        if api_proc.poll() is None:
            api_proc.terminate()
            try:
                api_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                api_proc.kill()


def main(argv: list[str] | None = None) -> int:
    argv = list(argv or sys.argv[1:])
    parser = argparse.ArgumentParser(description="Single launcher for ctf_ytdl_forensics")
    parser.add_argument("--install-runtime", action="store_true", help="Install or update Python runtime dependencies")
    parser.add_argument("--api-port", type=int, default=8000, help="Port for the local Python API")
    parser.add_argument("--web-port", type=int, default=5173, help="Port for the local web UI")
    args = parser.parse_args(argv)

    code = ensure_venv()
    if code != 0:
        return code

    if not in_project_venv():
        return reexec_in_venv(argv)

    if args.install_runtime:
        return install_runtime(python_exe=VENV_PYTHON)

    code = install_runtime(python_exe=VENV_PYTHON)
    if code != 0:
        return code

    return launch_web(api_port=args.api_port, web_port=args.web_port)


if __name__ == "__main__":
    raise SystemExit(main())
