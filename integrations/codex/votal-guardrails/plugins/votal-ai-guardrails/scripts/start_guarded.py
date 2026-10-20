"""Launch a local Codex process with an in-memory Votal credential."""
import argparse
import getpass
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "hooks"))
import check_prompt


def resolve_command(args):
    if args.cli:
        executable = shutil.which("codex")
        if not executable:
            raise ValueError("Codex CLI was not found on PATH. Install it first.")
        return [executable]
    path = Path(args.app).expanduser().resolve()
    if path.suffix == ".app":
        path = path / "Contents/MacOS/Codex"
    if not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError("App executable not found. Supply your installed Codex .app path or executable.")
    return [str(path)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--cli", action="store_true", help="Start the installed Codex CLI")
    mode.add_argument("--app", help="Path to a local Codex executable or macOS Codex.app; quit existing instances first")
    mode.add_argument("--check", action="store_true", help="Check connectivity with one harmless synthetic message; does not start Codex")
    parser.add_argument("--shield-url", default=os.environ.get("VOTAL_SHIELD_URL", check_prompt.DEFAULT_URL), help="Trusted HTTPS data-plane base URL receiving prompts and the key")
    args = parser.parse_args()
    try:
        command = None if args.check else resolve_command(args)
        if not os.environ.get("VOTAL_API_KEY"):
            if not sys.stdin.isatty():
                raise ValueError("Run in an interactive terminal or provide VOTAL_API_KEY through your approved environment manager.")
            print("Data plane: " + args.shield_url)
            key = getpass.getpass("Your Votal tenant API key (hidden): ").strip()
            if not key:
                raise ValueError("No key entered; Codex was not started.")
            os.environ["VOTAL_API_KEY"] = key
        os.environ["VOTAL_SHIELD_URL"] = args.shield_url
        check_prompt.load_settings()
        result = check_prompt.evaluate({"hook_event_name": "UserPromptSubmit", "prompt": "Hello. This is a synthetic connectivity test."})
        if result:
            print(result["reason"], file=sys.stderr)
            print("Preflight did not pass; Codex was not started. This is not proof of a pricing-policy block.", file=sys.stderr)
            return 1
        print("Votal preflight allowed the synthetic message. This does not verify hook activation or confidential-pricing policy.")
        if args.check:
            return 0
        print("Review and trust the installed UserPromptSubmit hook before relying on automatic checks.")
        print("This launch keeps the key in process memory. Start with this launcher again after quitting Codex.")
        return subprocess.call(command, env=os.environ.copy(), shell=False)
    except (ValueError, OSError, KeyboardInterrupt, EOFError):
        print("Setup did not complete. Check your executable path, HTTPS endpoint, credential, and terminal input.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
