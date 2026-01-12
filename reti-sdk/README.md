# Reti SDK

Python SDK for **Reti Social** — a privacy-first social protocol built on [Reticulum](https://reticulum.network/) and LXMF.

## Installation

```bash
pip install reti-sdk
```

Or install from source:

```bash
pip install -e .
```

## Quick Start

```python
from reti import RetiClient

# Initialize client
client = RetiClient()
client.start()

# Get your identity
print(f"Your address: {client.address}")

# Set your profile
client.set_profile(display_name="Alice", bio="Hello Reti!")

# Send a follow request
client.follow("destination_hash_here")

# Create a post (delivered to followers)
client.post("Hello, world!")

# Send a direct message
client.send_dm("destination_hash", "Hey there!")

# Listen for events
@client.on_message
def handle_message(msg):
    print(f"New message from {msg.source}: {msg.content}")

@client.on_post
def handle_post(post):
    print(f"New post from {post.author}: {post.content}")

# Keep running (in your application loop)
import time
while client.is_running:
    time.sleep(1)
```

## Features

- **Identity Management** — Create and persist Reticulum identities
- **Direct Messages** — LXMF-compatible encrypted DMs with attachments
- **Social Feed** — Post to followers with strict follow-only delivery
- **Follow Protocol** — Request, accept, reject follows with blocking
- **Group Chat** — Create groups, invite members, send group messages
- **Profiles** — Set and request user profiles
- **Attachments** — Send files up to 5MB with messages and posts

## Architecture

```
reti/
├── client.py      # Main RetiClient facade (DMs, posts, follows, groups, blogs)
├── identity.py    # Identity management
├── transport.py   # Reticulum/LXMF transport layer
├── storage.py     # SQLite persistence
├── attachments.py # File attachment handling
└── types.py       # Data classes
```

## License

MIT
