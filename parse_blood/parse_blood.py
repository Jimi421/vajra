#!/usr/bin/env python3

import json
import sys

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <bloodhound-graph.json>")
    sys.exit(1)

with open(sys.argv[1], "r") as f:
    data = json.load(f)

users = []

for node in data.get("nodes", {}).values():
    if node.get("kind") == "User":
        label = node.get("label", "")
        username = label.split("@")[0].lower()

        if username:
            users.append(username)

users = sorted(set(users))

with open("users.txt", "w") as f:
    for user in users:
        f.write(user + "\n")

print(f"[+] Wrote {len(users)} usernames to users.txt")
