"""Flask REST API for pf_analyzer — exposes all five CLI subcommands."""

from __future__ import annotations

import argparse
import io
import os
from contextlib import redirect_stdout

from flask import Flask, jsonify, request, send_from_directory

from pf_analyzer.cli import cmd_nat, cmd_rules, cmd_tables, cmd_topology, cmd_trace
from pf_analyzer.errors import PfAnalyzerError
from pf_analyzer.parser import parse_source

app = Flask(__name__, static_folder=None)

# One active config at a time (single-user dev server).
_state: dict = {"config": None, "filename": None}

WEBAPP_DIR = os.path.join(os.path.dirname(__file__), "webapp")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _capture(fn, *args):
    buf = io.StringIO()
    with redirect_stdout(buf):
        fn(*args)
    return buf.getvalue()


def _require_config():
    if _state["config"] is None:
        return jsonify({"error": "No config loaded"}), 400
    return None


# ---------------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(WEBAPP_DIR, "index.html")


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@app.route("/api/upload", methods=["POST"])
def api_upload():
    text: str | None = None
    filename = "pf.conf"

    if request.files:
        f = next(iter(request.files.values()))
        filename = f.filename or filename
        text = f.read().decode("utf-8", errors="replace")
    elif request.data:
        text = request.data.decode("utf-8", errors="replace")
        filename = request.headers.get("X-Filename", filename)
    else:
        return jsonify({"error": "No file data received"}), 400

    try:
        config = parse_source(text)
    except PfAnalyzerError as e:
        return jsonify({"error": str(e)}), 400

    _state["config"] = config
    _state["filename"] = filename

    return jsonify({
        "filename": filename,
        "filter_rules": len(config.filter_rules),
        "nat_rules": len(config.nat_rules),
        "rdr_rules": len(config.rdr_rules),
        "tables": len(config.tables),
    })


@app.route("/api/status")
def api_status():
    if _state["config"] is None:
        return jsonify({"loaded": False})
    config = _state["config"]
    return jsonify({
        "loaded": True,
        "filename": _state["filename"],
        "filter_rules": len(config.filter_rules),
        "nat_rules": len(config.nat_rules),
        "rdr_rules": len(config.rdr_rules),
        "tables": len(config.tables),
    })


@app.route("/api/topology")
def api_topology():
    err = _require_config()
    if err:
        return err
    output = _capture(cmd_topology, _state["config"])
    return jsonify({"output": output})


@app.route("/api/rules")
def api_rules():
    err = _require_config()
    if err:
        return err
    ns = argparse.Namespace(
        interface=request.args.get("interface") or None,
        action=request.args.get("action") or None,
        expanded=request.args.get("expanded", "").lower() in ("1", "true", "yes"),
    )
    output = _capture(cmd_rules, _state["config"], ns)
    return jsonify({"output": output})


@app.route("/api/tables")
def api_tables():
    err = _require_config()
    if err:
        return err
    ns = argparse.Namespace(name=request.args.get("name") or None)
    output = _capture(cmd_tables, _state["config"], ns)
    return jsonify({"output": output})


@app.route("/api/nat")
def api_nat():
    err = _require_config()
    if err:
        return err
    output = _capture(cmd_nat, _state["config"])
    return jsonify({"output": output})


@app.route("/api/trace", methods=["POST"])
def api_trace():
    err = _require_config()
    if err:
        return err

    body = request.get_json(silent=True) or {}

    src = body.get("src", "").strip()
    dst = body.get("dst", "").strip()
    proto = body.get("proto", "tcp").strip()

    if not src or not dst:
        return jsonify({"error": "src and dst are required"}), 400
    if proto not in ("tcp", "udp", "icmp", "icmp6", "gre", "esp"):
        return jsonify({"error": f"Invalid proto: {proto}"}), 400

    def _int_or_none(v):
        try:
            return int(v) if v not in (None, "") else None
        except (TypeError, ValueError):
            return None

    ns = argparse.Namespace(
        src=src,
        dst=dst,
        proto=proto,
        sport=_int_or_none(body.get("sport")),
        dport=_int_or_none(body.get("dport")),
        iface=body.get("iface") or None,
        direction=body.get("direction", "in"),
        icmp_type=_int_or_none(body.get("icmp_type")),
        suggest_fix=bool(body.get("suggest_fix", False)),
    )

    try:
        output = _capture(cmd_trace, _state["config"], ns)
    except PfAnalyzerError as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({"output": output})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
