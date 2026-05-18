#!/usr/bin/env python3
"""Pair a SwitchBot Keypad with the switchbot-keypad-bridge ESP32 device.

Usage:
    python pair_keypad.py KEYPAD_MAC ESP_MAC SHARED_KEY --user EMAIL [--password PASSWORD]

Where to find the addresses:
    KEYPAD_MAC  SwitchBot app -> open the keypad device -> ... -> Device Info -> BLE Address
    ESP_MAC     ESPHome boot log ("BLE address: ...") or Home Assistant device page ("BLE MAC" sensor)

The keypad model is auto-detected from the SwitchBot cloud device list and
the right pairing dialect is selected automatically.
"""

import argparse
import asyncio
import getpass
import json
import sys
import urllib.request

from bleak import BleakClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_SWITCHBOT_CLIENT_ID = "5nnwmhmsa9xxskm14hd85lm9bm"
_API_ACCOUNT_BASE = "https://account.api.switchbot.net"
_UUID_RX = "cba20002-224d-11e6-9fb8-0002a5d5c51b"
_UUID_TX = "cba20003-224d-11e6-9fb8-0002a5d5c51b"
_ACK_TIMEOUT = 3.0


# ---------------------------------------------------------------------------
# SwitchBot cloud
# ---------------------------------------------------------------------------

def _api_post(url: str, data: dict | None = None, headers: dict | None = None) -> dict:
    body = json.dumps(data or {}).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=10) as resp:
        result = json.loads(resp.read())
    if result.get("statusCode") != 100:
        raise RuntimeError(
            f"SwitchBot API error {result.get('statusCode')}: {result.get('message')}"
        )
    return result["body"]


def _login(username: str, password: str) -> dict[str, str]:
    """Authenticate against the SwitchBot account API. Returns request headers."""
    auth = _api_post(
        f"{_API_ACCOUNT_BASE}/account/api/v1/user/login",
        {
            "clientId": _SWITCHBOT_CLIENT_ID,
            "username": username,
            "password": password,
            "grantType": "password",
            "verifyCode": "",
        },
    )
    return {"authorization": auth["access_token"]}


def _resolve_region(auth_headers: dict[str, str]) -> str:
    try:
        userinfo = _api_post(
            f"{_API_ACCOUNT_BASE}/account/api/v1/user/userinfo",
            headers=auth_headers,
        )
        return userinfo.get("botRegion") or "us"
    except Exception:
        return "us"


def _normalise_mac(mac: str) -> str:
    return mac.replace(":", "").replace("-", "").upper()


def fetch_device_type(keypad_mac: str, region: str, auth_headers: dict[str, str]) -> str | None:
    """Look up the SwitchBot cloud `device_type` string for the given MAC.

    Returns None if the device is not in the account or the API omits the
    field. The string itself is a SwitchBot SKU / model code (e.g.
    `"WoKeypad"`, `"WoKeypadTouch"`, `"WoKeypadVision"`) and is mapped to
    a protocol family by `classify_device_type`.
    """
    devices = _api_post(
        f"https://wonderlabs.{region}.api.switchbot.net/wonder/device/v3/getdevice",
        {"required_type": "All"},
        auth_headers,
    )
    target = _normalise_mac(keypad_mac)
    for item in devices.get("Items", []):
        if _normalise_mac(item.get("device_mac", "")) != target:
            continue
        detail = item.get("device_detail") or {}
        return detail.get("device_type")
    return None


def fetch_keypad_credentials(keypad_mac: str, region: str, auth_headers: dict[str, str]) -> tuple[int, bytes]:
    comm = _api_post(
        f"https://wonderlabs.{region}.api.switchbot.net/wonder/keys/v1/communicate",
        {"device_mac": _normalise_mac(keypad_mac), "keyType": "user"},
        auth_headers,
    )
    key_info = comm["communicationKey"]
    return int(key_info["keyId"], 16), bytes.fromhex(key_info["key"])


# ---------------------------------------------------------------------------
# Keypad-family classification and pairing presets
# ---------------------------------------------------------------------------
#
# Different keypad families speak slightly different dialects of the same
# pairing ceremony. We identify the family from the `device_type` string
# the SwitchBot cloud reports for the keypad (the same field pySwitchbot
# parses out of `wonder/device/v3/getdevice`). Examples observed in the
# wild: "WoKeypad", "WoKeypadTouch", "WoKeypadVision".

# Exact device_type → preset key. Anything not listed here goes through
# the heuristic fallback in `classify_device_type`.
DEVICE_TYPE_TO_PRESET = {
    "WoKeypad":           ("Keypad",             "original"),
    "WoKeypadTouch":      ("Keypad Touch",       "original"),
    "WoKeypadVision":     ("Keypad Vision",      "vision"),
    "WoKeypadVisionPro":  ("Keypad Vision Pro",  "vision"),
}

# Pairing dialect per family. The bridge firmware learns the shared_slot
# at runtime from the IV-request frame, so nothing here needs to be
# mirrored on the device side.
KEYPAD_PRESETS = {
    "original": {
        "shared_slot": 0x88,
        "slot_init_nonce": 0x69,
        "enter_pairing": bytes.fromhex("0f52010700"),
        "capabilities_probe": None,
        "finalize_tail": bytes.fromhex("000809040507"),
    },
    "vision": {
        "shared_slot": 0xC6,
        "slot_init_nonce": 0x80,
        "enter_pairing": bytes.fromhex("0f530107"),
        "capabilities_probe": bytes.fromhex("0f530703"),
        "finalize_tail": bytes.fromhex("040401050809"),
    },
}


def classify_device_type(device_type: str) -> tuple[str, str]:
    """Map a cloud `device_type` string to (friendly_name, preset_key).

    Unknown SKUs are rejected — the table above is the single source of
    truth and must be extended explicitly when SwitchBot ships a new model.
    """
    if device_type not in DEVICE_TYPE_TO_PRESET:
        raise RuntimeError(
            f"Unsupported keypad SKU {device_type!r}. Known SKUs: "
            + ", ".join(sorted(DEVICE_TYPE_TO_PRESET))
        )
    return DEVICE_TYPE_TO_PRESET[device_type]


# ---------------------------------------------------------------------------
# BLE pairing
# ---------------------------------------------------------------------------

class Pairer:
    def __init__(self, client: BleakClient, key_id: int, key: bytes):
        self._client = client
        self._key_id = key_id
        self._key = key
        self._iv: bytes | None = None
        self._event = asyncio.Event()

    def _on_notify(self, _sender, data: bytearray):
        if len(data) == 20 and data[0] == 0x01 and data[1] == 0x00:
            self._iv = bytes(data[4:20])
        self._event.set()

    async def start(self):
        await self._client.start_notify(_UUID_TX, self._on_notify)

    async def _wait(self):
        await asyncio.wait_for(self._event.wait(), timeout=_ACK_TIMEOUT)

    async def request_iv(self):
        self._event.clear()
        await self._client.write_gatt_char(
            _UUID_RX,
            bytes([0x57, 0x00, 0x00, 0x00, 0x0F, 0x21, 0x03, self._key_id]),
            response=True,
        )
        await self._wait()
        if self._iv is None:
            raise RuntimeError(
                "Keypad did not open a session. Make sure the keypad is in pairing mode."
            )

    async def send(self, plaintext: bytes):
        assert self._iv is not None
        ct = (
            Cipher(algorithms.AES128(self._key), modes.CTR(self._iv))
            .encryptor()
            .update(plaintext)
        )
        self._event.clear()
        await self._client.write_gatt_char(
            _UUID_RX,
            bytes([0x57, self._key_id]) + self._iv[:2] + ct,
            response=True,
        )
        try:
            await self._wait()
        except asyncio.TimeoutError:
            pass


async def _run_pairing(
    keypad_mac: str,
    esp_mac: str,
    shared_token: bytes,
    key_id: int,
    key: bytes,
    preset_key: str,
):
    preset = KEYPAD_PRESETS[preset_key]
    slot = preset["shared_slot"]
    nonce = preset["slot_init_nonce"]

    print("Pairing...")
    async with BleakClient(keypad_mac) as client:
        p = Pairer(client, key_id, key)
        await p.start()

        await p.request_iv()

        esp_mac_bytes = bytes.fromhex(esp_mac.replace(":", ""))

        await p.send(preset["enter_pairing"])
        if preset["capabilities_probe"] is not None:
            await p.send(preset["capabilities_probe"])
        await p.send(bytes.fromhex("0603"))
        await p.send(bytes([0x0F, 0x20, 0x03, slot, nonce]))
        await p.send(bytes([0x0F, 0x20, 0x04, slot, 0x00]) + shared_token[:8])
        await p.send(bytes([0x0F, 0x20, 0x04, slot, 0x01]) + shared_token[8:])
        await p.send(bytes([0x06, 0x01, slot]) + esp_mac_bytes)
        await p.send(bytes.fromhex("0f520202") + bytes([0x10, 0xFF, 0x05, 0x06]) + preset["finalize_tail"])
        await p.send(bytes.fromhex("0f530106"))

    print("Done. Press any key on the keypad to verify.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Pair a SwitchBot Keypad with the switchbot-keypad-bridge ESP32 device.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Where to find the addresses:\n"
            "  KEYPAD_MAC  SwitchBot app -> open the keypad device -> ... -> Device Info -> BLE Address\n"
            "  ESP_MAC     ESPHome boot log ('BLE address: ...') or Home Assistant device page ('BLE MAC' sensor)"
        ),
    )
    parser.add_argument("keypad_mac", metavar="KEYPAD_MAC", help="BLE MAC of the SwitchBot Keypad.")
    parser.add_argument("esp_mac", metavar="ESP_MAC", help="BLE MAC of the ESP32 running switchbot-keypad-bridge.")
    parser.add_argument("shared_key", metavar="SHARED_KEY", help="32-hex-char key from generate_key.py, matching switchbot_shared_key in secrets.yaml.")
    parser.add_argument("-u", "--user", required=True, help="SwitchBot account email address.")
    parser.add_argument("-p", "--password", default=None, help="SwitchBot account password (prompted if omitted).")
    args = parser.parse_args()

    if len(args.shared_key) != 32:
        parser.error("SHARED_KEY must be exactly 32 hex characters (16 bytes).")
    try:
        shared_token = bytes.fromhex(args.shared_key)
    except ValueError:
        parser.error("SHARED_KEY must contain only hex characters (0-9, a-f).")

    password = args.password or getpass.getpass("SwitchBot password: ")

    try:
        auth_headers = _login(args.user, password)
        region = _resolve_region(auth_headers)

        device_type = fetch_device_type(args.keypad_mac, region, auth_headers)
        if device_type is None:
            print(
                f"Error: {args.keypad_mac} is not in this SwitchBot account.",
                file=sys.stderr,
            )
            sys.exit(1)
        friendly, preset_key = classify_device_type(device_type)

        key_id, key = fetch_keypad_credentials(args.keypad_mac, region, auth_headers)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(
            f"Could not reach the SwitchBot cloud. Check your credentials and internet connection. ({exc})",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"Detected keypad: {friendly}")

    try:
        asyncio.run(_run_pairing(args.keypad_mac, args.esp_mac, shared_token, key_id, key, preset_key))
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(
            f"Could not connect to the keypad. Make sure Bluetooth is enabled and the keypad is nearby. ({exc})",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
