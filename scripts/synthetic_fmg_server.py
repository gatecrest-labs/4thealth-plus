"""Serve SyntheticFMG as a fake FortiManager over HTTPS (Docker test rig only).

Lets the real web and collector processes run against ~1,000 synthetic
devices, so load behaviour can be watched on a laptop. Never used in
production. Configuration (environment):

    SYNTH_DEVICES (1000)   SYNTH_ADOMS (5)   SYNTH_LATENCY_MS_MIN/MAX (0)
    SYNTH_ERROR_RATE (0.0) SYNTH_SEED (1)    SYNTH_PORT (8443)
    SYNTH_CERT / SYNTH_KEY (certs/cert.pem, certs/key.pem)

``POST /jsonrpc`` speaks FMG JSON-RPC; ``GET /_calls`` returns the call
counters the synthetic FMG has recorded.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import requests
from flask import Flask, jsonify, request

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.synthetic_fmg import SyntheticFMG


def create_server_app(synth: SyntheticFMG) -> Flask:
    """Wrap *synth* in a Flask app exposing /jsonrpc and /_calls."""
    flask_app = Flask(__name__)

    @flask_app.post("/jsonrpc")
    def jsonrpc():
        body = request.get_json(force=True, silent=True) or {}
        try:
            return jsonify(synth.post(body))
        except requests.ConnectionError as exc:
            return jsonify({"error": str(exc)}), 502

    @flask_app.get("/_calls")
    def calls():
        return jsonify(
            {
                "total": synth.total_calls,
                "calls": dict(synth.calls),
                "unsupported": dict(synth.unsupported),
                "proxy_calls": dict(synth.proxy_calls),
            }
        )

    return flask_app


def main() -> None:
    env = os.environ.get
    synth = SyntheticFMG(
        devices=int(env("SYNTH_DEVICES", "1000")),
        adoms=int(env("SYNTH_ADOMS", "5")),
        latency_ms=(
            float(env("SYNTH_LATENCY_MS_MIN", "0")),
            float(env("SYNTH_LATENCY_MS_MAX", "0")),
        ),
        error_rate=float(env("SYNTH_ERROR_RATE", "0")),
        seed=int(env("SYNTH_SEED", "1")),
    )
    create_server_app(synth).run(
        host="0.0.0.0",
        port=int(env("SYNTH_PORT", "8443")),
        ssl_context=(
            env("SYNTH_CERT", "certs/cert.pem"),
            env("SYNTH_KEY", "certs/key.pem"),
        ),
        threaded=True,
    )


if __name__ == "__main__":
    main()
