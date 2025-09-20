#!/usr/bin/env python3
"""
List Secret Scanning alerts for a GitHub repository.

Usage:
  export GITHUB_TOKEN="ghp_xxx"     # or pass --token
  python list_secret_scanning_alerts.py --owner redwindows17 --repo wazuh --hide-secret

Requirements:
  pip install requests
"""

import os
import sys
import argparse
import requests
import json

API_BASE = "https://api.github.com"

def fetch_alerts(owner, repo, token, hide_secret=False, per_page=100):
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    params = {
        "per_page": per_page
    }
    if hide_secret:
        params["hide_secret"] = "true"

    url = f"{API_BASE}/repos/{owner}/{repo}/secret-scanning/alerts"
    page = 1
    all_alerts = []
    while True:
        params["page"] = page
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        if resp.status_code == 404:
            raise SystemExit(f"404 Not Found — check repository name, or whether secret scanning is enabled / you have permission.")
        resp.raise_for_status()
        alerts = resp.json()
        if not alerts:
            break
        all_alerts.extend(alerts)
        # Pagination: check Link header for next page, or break if fewer than per_page
        if "Link" in resp.headers:
            if 'rel="next"' not in resp.headers["Link"]:
                break
        if len(alerts) < per_page:
            break
        page += 1
    return all_alerts

def pretty_print(alerts):
    if not alerts:
        print("No secret-scanning alerts found.")
        return
    # Print header
    print(f"{'#':<6} {'type':<15} {'state':<10} {'created_at':<25} {'locations_count':<15} {'secret_snippet'}")
    for a in alerts:
        num = a.get("number") or a.get("id") or "-"
        secret_type = a.get("secret_type", "-")
        state = a.get("state", "-")
        created = a.get("created_at", "-")
        locations = len(a.get("locations", [])) if a.get("locations") is not None else "-"
        # secret literal may be hidden; if present, show a masked snippet
        secret = a.get("secret")
        secret_snippet = "-"
        if secret is None:
            secret_snippet = "(hidden or not returned)"
        else:
            # show short masked snippet (do NOT print full secret)
            s = str(secret)
            if len(s) > 12:
                secret_snippet = f"{s[:6]}...{s[-4:]}"  # masked
            else:
                secret_snippet = s
        print(f"{str(num):<6} {secret_type:<15} {state:<10} {created:<25} {str(locations):<15} {secret_snippet}")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--owner", required=True, help="Repo owner/org (example: redwindows17)")
    p.add_argument("--repo", required=True, help="Repository name (example: wazuh)")
    p.add_argument("--token", default=os.getenv("GITHUB_TOKEN"), help="GitHub token (or set GITHUB_TOKEN)")
    p.add_argument("--hide-secret", action="store_true", help="Pass hide_secret=true to avoid returning secret literal")
    p.add_argument("--save", help="Save raw JSON to this file (optional)")
    args = p.parse_args()

    if not args.token:
        raise SystemExit("Error: provide a GitHub token via --token or $GITHUB_TOKEN")

    try:
        alerts = fetch_alerts(args.owner, args.repo, args.token, hide_secret=args.hide_secret)
    except requests.HTTPError as e:
        print("HTTP error:", e)
        print("Response:", getattr(e.response, "text", ""))
        sys.exit(1)
    except Exception as e:
        print("Error:", e)
        sys.exit(1)

    pretty_print(alerts)

    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2, ensure_ascii=False)
        print(f"\nSaved {len(alerts)} alerts to {args.save}")

if __name__ == "__main__":
    main()