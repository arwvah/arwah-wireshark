#!/usr/bin/env python3
"""Install Arwah plugins; back up replaced/removed copies outside plugin search paths."""
import argparse
from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uninstall", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    folders = subprocess.run(["tshark", "-G", "folders"], capture_output=True,
                             text=True, check=True).stdout
    directory = None
    for line in folders.splitlines():
        if line.startswith("Personal Lua Plugins:"):
            directory = Path(line.split(":", 1)[1].strip())
            break
    if directory is None:
        raise SystemExit("Personal Lua plugin folder not found. Use Help > About > Folders for manual installation.")
    backup = Path.home() / ".arwah-wireshark-backups" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    for name in ("arwah_dns.lua", "arwah_traffic.lua"):
        source, target = root / name, directory / name
        if target.exists() and (args.uninstall or target.read_bytes() != source.read_bytes()):
            backup.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, backup / name)
            print(f"Backed up: {backup / name}")
        if args.uninstall:
            if target.exists():
                target.unlink()
                print(f"Removed: {target}")
        else:
            directory.mkdir(parents=True, exist_ok=True)
            temporary = target.with_suffix(".lua.pending")
            shutil.copy2(source, temporary)
            temporary.replace(target)
            print(f"Installed: {target}")
    print("Restart Wireshark or use Analyze > Reload Lua Plugins.")


if __name__ == "__main__":
    main()
