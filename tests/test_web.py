"""Tests for the local web server: routing, security guards, and a full
upload -> analyze -> download cycle over real HTTP."""

import http.client
import json
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from ctre.web import make_server


@pytest.fixture()
def server():
    httpd = make_server(port=0)  # ephemeral port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()
    httpd.workspace.cleanup()


def _conn(server):
    return http.client.HTTPConnection("127.0.0.1", server.server_address[1])


def _req(server, method, path, body=None, headers=None):
    c = _conn(server)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, r.getheaders(), data


def test_index_served_with_csp(server):
    status, headers, body = _req(server, "GET", "/")
    assert status == 200
    hd = dict((k.lower(), v) for k, v in headers)
    assert "content-security-policy" in hd
    assert b"Cyber Threat Reconstruction Engine" in body


def test_api_requires_header(server):
    status, _, _ = _req(server, "GET", "/api/state")
    assert status == 403
    status, _, body = _req(server, "GET", "/api/state", headers={"X-CTRE": "1"})
    assert status == 200
    assert json.loads(body)["files"] == {}


def test_bad_host_rejected(server):
    status, _, _ = _req(server, "GET", "/api/state",
                        headers={"X-CTRE": "1", "Host": "evil.example.com"})
    assert status == 403


def test_full_cycle_with_sample(server):
    h = {"X-CTRE": "1"}
    status, _, body = _req(server, "POST", "/api/sample", headers=h)
    assert status == 200
    assert set(json.loads(body)["files"]) == {"mft", "usnjrnl", "pcap"}

    status, _, body = _req(server, "POST", "/api/analyze",
                           body=json.dumps({"min_exfil_bytes": 100000}),
                           headers={**h, "Content-Type": "application/json"})
    assert status == 200
    result = json.loads(body)
    assert result["summary"]["findings"] == 3
    rules = {f["rule"] for f in result["findings"]}
    assert "SI_BEFORE_FN" in rules
    assert result["summary"]["correlations"] >= 1

    status, headers, body = _req(server, "GET", "/api/report", headers=h)
    assert status == 200
    hd = dict((k.lower(), v) for k, v in headers)
    assert "attachment" in hd.get("content-disposition", "")
    assert b"SI_BEFORE_FN" in body

    status, _, body = _req(server, "GET", "/api/export", headers=h)
    assert status == 200
    assert json.loads(body)["summary"]["findings"] == 3


def test_upload_and_remove(server):
    h = {"X-CTRE": "1"}
    status, _, body = _req(server, "POST", "/api/upload?kind=pcap&name=x.pcap",
                           body=b"not a real pcap",
                           headers={**h, "Content-Type":
                                    "application/octet-stream"})
    assert status == 200
    assert "pcap" in json.loads(body)["files"]

    # pcap fails to parse -> analyze returns a clean 422, not a crash.
    status, _, body = _req(server, "POST", "/api/analyze", body="{}",
                           headers={**h, "Content-Type": "application/json"})
    assert status == 422

    status, _, body = _req(server, "POST", "/api/remove?kind=pcap", headers=h)
    assert status == 200
    assert json.loads(body)["files"] == {}


def test_analyze_rejects_out_of_range_options(server):
    h = {"X-CTRE": "1"}
    _req(server, "POST", "/api/sample", headers=h)
    status, _, _ = _req(server, "POST", "/api/analyze",
                        body=json.dumps({"window_minutes": 99999}),
                        headers={**h, "Content-Type": "application/json"})
    assert status == 400


def test_unknown_api_route(server):
    status, _, _ = _req(server, "POST", "/api/nope",
                        headers={"X-CTRE": "1"})
    assert status == 404
