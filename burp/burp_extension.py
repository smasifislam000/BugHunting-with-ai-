"""
burp/burp_extension.py
----------------------
Jython extension for Burp Suite Pro.
Passively captures all in-scope traffic and forwards structured
records to the framework's SQLite DB and JSON log.

INSTALL (Burp Suite Pro):
  1. Extender → Options → Python Environment → set Jython standalone JAR.
  2. Extender → Extensions → Add → Extension Type: Python
  3. Select this file: burp_extension.py

NOTE:
  - Jython is Python 2.7 syntax. This file is written to work under Jython 2.7.
  - It does NOT import the framework (Jython cannot see modern Python 3).
  - It writes plain JSONL files that the framework ingests later.
"""

# Jython imports
from burp import IBurpExtender, IHttpListener
from java.io import PrintWriter
import json
import os
import time

# ─────────────────────────────────────────
# Config (edit these)
# ─────────────────────────────────────────
OUTPUT_DIR = os.path.expanduser("~/dream_framework/results/burp_capture")
os.makedirs(OUTPUT_DIR) if not os.path.exists(OUTPUT_DIR) else None
CAPTURE_FILE = os.path.join(OUTPUT_DIR, "burp_traffic.jsonl")
MAX_BODY = 5000  # truncate large bodies


class BurpExtender(IBurpExtender, IHttpListener):

    # ─────────────────────────────────────
    # IBurpExtender
    # ─────────────────────────────────────
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Dream Framework Capture")
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        callbacks.registerHttpListener(self)
        self._stdout.println("[Dream] Capture extension loaded")
        self._stdout.println("[Dream] Output: " + CAPTURE_FILE)

    # ─────────────────────────────────────
    # IHttpListener
    # ─────────────────────────────────────
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Only capture responses to avoid duplicate request/response records
        if messageIsRequest:
            return
        try:
            self._capture(messageInfo)
        except Exception, e:  # noqa: E999 (Jython 2.7 syntax)
            self._stderr.println("[Dream] capture error: " + str(e))

    def _capture(self, messageInfo):
        request = messageInfo.getRequest()
        response = messageInfo.getResponse()
        if request is None or response is None:
            return

        service = messageInfo.getHttpService()
        host = service.getHost()
        port = service.getPort()
        proto = service.getProtocol()

        req_info = self._helpers.analyzeRequest(messageInfo)
        resp_info = self._helpers.analyzeResponse(response)

        url = str(req_info.getUrl())
        method = str(req_info.getMethod())
        status = int(resp_info.getStatusCode())

        # Bodies
        req_body = ""
        resp_body = ""
        try:
            req_body = self._extract_body(request, req_info.getBodyOffset())
            resp_body = self._extract_body(response, resp_info.getBodyOffset())
        except Exception:
            pass

        # Headers
        req_headers = [str(h) for h in req_info.getHeaders()]
        resp_headers = [str(h) for h in resp_info.getHeaders()]

        record = {
            "ts": time.time(),
            "host": str(host),
            "port": port,
            "protocol": str(proto),
            "method": method,
            "url": url,
            "status": status,
            "request_headers": req_headers[:50],
            "response_headers": resp_headers[:50],
            "request_body": req_body[:MAX_BODY],
            "response_body": resp_body[:MAX_BODY],
            "tool": str(toolFlag),
        }

        # Append as JSONL (Jython 2.7 compatible)
        try:
            f = open(CAPTURE_FILE, "a")
            try:
                f.write(json.dumps(record))
                f.write("\n")
            finally:
                f.close()
        except Exception, e:
            self._stderr.println("[Dream] write error: " + str(e))

    def _extract_body(self, message, offset):
        try:
            body_bytes = message[offset:]
            return self._helpers.bytesToString(body_bytes)
        except Exception:
            return ""


# ─────────────────────────────────────────
# Helper: how to load this in Burp
# ─────────────────────────────────────────
"""
LOADING INSTRUCTIONS
====================

1. Download Jython standalone JAR (2.7.x):
   https://www.jython.org/download

2. Burp Suite Pro:
   Extender → Options → Python Environment
   → Set "Location of Jython standalone JAR file"

3. Extender → Extensions → Add
   → Extension Type: Python
   → Extension file: burp/burp_extension.py

4. Output will appear in:
   results/burp_capture/burp_traffic.jsonl

5. The framework's ingestor (later step) reads this JSONL and
   imports captured traffic into the SQLite DB.
"""