#!/usr/bin/env python3
"""
Ghost Gate M8 — Fixture Telegram Bot API server.

Implements the minimal subset of the Telegram Bot API needed to run the real
ghost-gate-telegram binary against a local test bridge without a real bot token or
Telegram group. Never connects to Telegram. Never modifies any real group.

Usage:
    python3 fixture-telegram-server.py <port> <chat_id>

Example:
    python3 fixture-telegram-server.py 7810 -1001234567890

Endpoints served:
    GET  /bot{token}/getMe
    POST /bot{token}/getUpdates       — long-poll; returns queued updates immediately
    POST /bot{token}/sendMessage      — records the call; returns ok
    POST /bot{token}/approveChatJoinRequest   — records; returns ok
    POST /bot{token}/declineChatJoinRequest   — records; returns ok
    POST /bot{token}/createChatInviteLink     — records; returns a fixture invite link
    GET  /bot{token}/getChatMember    — returns a fixture member status
    POST /fixture/inject              — enqueue a test update (JSON body = Telegram update object)
    GET  /fixture/results             — return all recorded outgoing bot calls as JSON
    DELETE /fixture/results           — clear the recorded calls list
"""
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

BOT_ID = 123456789
BOT_USERNAME = "fixture_bot"
BOT_FIRST_NAME = "Fixture"

# Shared state protected by a lock
_lock = threading.Lock()
_pending_updates = []          # list of Telegram update dicts, consumed by getUpdates
_recorded_calls = []           # list of {method, params, timestamp} dicts
_next_update_id = 10001        # auto-increment for injected updates


def _get_ok(result):
    return json.dumps({"ok": True, "result": result}).encode()


def _get_err(description, error_code=400):
    return json.dumps({"ok": False, "error_code": error_code, "description": description}).encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Route fixture server logs to stderr so they don't clutter stdout
        sys.stderr.write("[fixture-tg] " + fmt % args + "\n")

    def _send(self, code, body, content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length > 0 else b""

    def _parse_token(self, path):
        """Extract the bot token from /bot<token>/<method>."""
        # path is like /bot<token>/<method>
        parts = path.lstrip("/").split("/", 2)
        if len(parts) < 2 or not parts[0].startswith("bot"):
            return None, None
        token = parts[0][3:]  # strip 'bot' prefix
        method = parts[1] if len(parts) > 1 else ""
        return token, method

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path.startswith("/bot"):
            token, method = self._parse_token(path)
            if method == "getMe":
                body = _get_ok({
                    "id": BOT_ID,
                    "is_bot": True,
                    "first_name": BOT_FIRST_NAME,
                    "username": BOT_USERNAME,
                    "can_join_groups": True,
                    "can_read_all_group_messages": False,
                    "supports_inline_queries": False,
                })
                self._send(200, body)
                return
            if method == "getChatMember":
                # Return a fake member so diagnostic checks pass
                qs = parse_qs(parsed.query)
                user_id = qs.get("user_id", ["0"])[0]
                body = _get_ok({
                    "status": "member",
                    "user": {
                        "id": int(user_id),
                        "is_bot": False,
                        "first_name": "Fixture",
                    },
                })
                self._send(200, body)
                return

        if path == "/fixture/results":
            with _lock:
                body = json.dumps(_recorded_calls, indent=2).encode()
            self._send(200, body)
            return

        self._send(404, b'{"ok":false,"description":"not found"}')

    def do_DELETE(self):
        global _recorded_calls
        if self.path == "/fixture/results":
            with _lock:
                _recorded_calls = []
            self._send(200, b'{"ok":true}')
            return
        self._send(404, b'{"ok":false,"description":"not found"}')

    def do_POST(self):
        global _next_update_id
        parsed = urlparse(self.path)
        path = parsed.path
        raw = self._read_body()

        # Fixture control endpoint: inject a test update
        if path == "/fixture/inject":
            try:
                update = json.loads(raw)
            except Exception as e:
                self._send(400, json.dumps({"error": str(e)}).encode())
                return
            with _lock:
                if "update_id" not in update:
                    update["update_id"] = _next_update_id
                    _next_update_id += 1
                _pending_updates.append(update)
            sys.stderr.write(f"[fixture-tg] injected update {update['update_id']}\n")
            self._send(200, json.dumps({"ok": True, "update_id": update["update_id"]}).encode())
            return

        if not path.startswith("/bot"):
            self._send(404, b'{"ok":false,"description":"not found"}')
            return

        token, method = self._parse_token(path)
        try:
            params = json.loads(raw) if raw else {}
        except Exception:
            params = {}

        # Record every outgoing bot call (what the bot sends to Telegram)
        with _lock:
            _recorded_calls.append({
                "method": method,
                "params": params,
                "timestamp": time.time(),
            })
        sys.stderr.write(f"[fixture-tg] bot called {method} params={json.dumps(params)[:200]}\n")

        if method == "getUpdates":
            offset = params.get("offset", 0)
            with _lock:
                pending = [u for u in _pending_updates if u.get("update_id", 0) >= offset]
                # Consume returned updates
                consumed_ids = {u["update_id"] for u in pending}
                _pending_updates[:] = [u for u in _pending_updates if u["update_id"] not in consumed_ids]
            self._send(200, _get_ok(pending))
            return

        if method == "sendMessage":
            chat_id = params.get("chat_id", 0)
            text = params.get("text", "")
            body = _get_ok({
                "message_id": 1,
                "from": {"id": BOT_ID, "is_bot": True, "first_name": BOT_FIRST_NAME, "username": BOT_USERNAME},
                "chat": {"id": chat_id, "type": "private"},
                "date": int(time.time()),
                "text": text,
            })
            self._send(200, body)
            return

        if method == "approveChatJoinRequest":
            self._send(200, _get_ok(True))
            return

        if method == "declineChatJoinRequest":
            self._send(200, _get_ok(True))
            return

        if method == "createChatInviteLink":
            chat_id = params.get("chat_id", 0)
            self._send(200, _get_ok({
                "invite_link": f"https://t.me/fixture_group/join/{int(time.time())}",
                "creator": {"id": BOT_ID, "is_bot": True, "first_name": BOT_FIRST_NAME},
                "creates_join_request": True,
                "is_primary": False,
                "is_revoked": False,
            }))
            return

        if method == "getChat":
            chat_id = params.get("chat_id", 0)
            self._send(200, _get_ok({
                "id": chat_id,
                "type": "supergroup",
                "title": "Fixture Test Group",
            }))
            return

        if method == "getChatAdministrators":
            chat_id = params.get("chat_id", 0)
            self._send(200, _get_ok([{
                "status": "administrator",
                "user": {"id": BOT_ID, "is_bot": True, "first_name": BOT_FIRST_NAME},
                "can_be_edited": False,
                "can_manage_chat": True,
                "can_invite_users": True,
            }]))
            return

        # Fallback: return ok for any other method so the bot doesn't crash
        self._send(200, _get_ok(True))


def make_join_command_update(user_id, chat_id, text="/join"):
    """Return a Telegram update dict for a /join command message."""
    return {
        "message": {
            "message_id": int(time.time()),
            "from": {"id": user_id, "is_bot": False, "first_name": "TestUser", "username": "testuser"},
            "chat": {"id": chat_id, "type": "supergroup", "title": "Fixture Test Group"},
            "date": int(time.time()),
            "text": text,
            "entities": [{"offset": 0, "length": len(text.split()[0]), "type": "bot_command"}],
        }
    }


def make_chat_join_request_update(user_id, chat_id):
    """Return a Telegram update dict for a chat_join_request event."""
    return {
        "chat_join_request": {
            "chat": {"id": chat_id, "type": "supergroup", "title": "Fixture Test Group"},
            "from": {"id": user_id, "is_bot": False, "first_name": "TestUser", "username": "testuser"},
            "date": int(time.time()),
            "user_chat_id": user_id,
        }
    }


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: fixture-telegram-server.py <port> <chat_id>", file=sys.stderr)
        sys.exit(1)
    port = int(sys.argv[1])
    chat_id = int(sys.argv[2])

    server = HTTPServer(("127.0.0.1", port), Handler)
    sys.stderr.write(f"[fixture-tg] listening on http://127.0.0.1:{port} (chat_id={chat_id})\n")
    sys.stderr.flush()
    # Signal readiness to the caller on stdout (one line, then flush)
    print(f"fixture-telegram-server ready on port {port}", flush=True)
    server.serve_forever()
