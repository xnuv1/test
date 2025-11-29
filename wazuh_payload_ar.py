import sys
import json
from payload_client import analyze_file  


def main():
    # Wazuh sends the alert JSON via stdin to the active response script
    raw = sys.stdin.read().strip()
    if not raw:
        print("[ERROR] No alert JSON received on stdin")
        return

    try:
        alert = json.loads(raw)
    except Exception as e:
        print(f"[ERROR] Failed to parse JSON from stdin: {e}")
        print(raw)
        return

    # Try multiple possible paths where the file path might live in syscheck alerts
    file_path = None

    # Common structure for syscheck alerts (FIM)
    # Depending on your Wazuh version, it may be: alert['syscheck']['path']
    # or alert['data']['syscheck']['path'], etc.
    candidates = [
        ("syscheck", "path"),
        ("data", "syscheck", "path"),
        ("rule", "file"),
    ]

    for keys in candidates:
        node = alert
        ok = True
        for k in keys:
            if isinstance(node, dict) and k in node:
                node = node[k]
            else:
                ok = False
                break
        if ok and isinstance(node, str):
            file_path = node
            break

    if not file_path:
        print("[ERROR] Could not find file path in alert JSON")
        print(json.dumps(alert, indent=2))
        return

    print(f"[INFO] Wazuh alert refers to file: {file_path}")
    analyze_file(file_path)


if __name__ == "__main__":
    main()
