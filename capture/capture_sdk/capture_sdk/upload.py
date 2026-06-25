"""Shared gateway-upload plumbing for capture tools (UploadCapture streaming)."""

from __future__ import annotations

import queue

from capture_sdk.proto import common_pb2 as cp
from capture_sdk.proto import ingest_pb2 as ip

SENTINEL = object()

_KINDS = {"pcap": cp.FILE_KIND_PCAP, "keylog": cp.FILE_KIND_KEYLOG}


def capture_chunks(session_id: str, q: "queue.Queue", max_chunk: int, upload_id: str = "capture"):
    """Yield CaptureChunk messages for IngestService.UploadCapture (STREAMING_LIVE).

    The queue carries ("pcap"|"keylog", bytes) items; SENTINEL ends the stream.
    Byte offsets are tracked per file so the gateway can order/resume.
    """
    yield ip.CaptureChunk(begin=ip.UploadBegin(
        session_id=session_id, upload_id=upload_id, mode=ip.CAPTURE_MODE_STREAMING_LIVE))
    offsets = {"pcap": 0, "keylog": 0}
    while True:
        item = q.get()
        if item is SENTINEL:
            break
        kind, payload = item
        for i in range(0, len(payload), max_chunk):
            part = payload[i : i + max_chunk]
            yield ip.CaptureChunk(data=ip.DataChunk(
                kind=_KINDS[kind], offset=offsets[kind], payload=part))
            offsets[kind] += len(part)
    yield ip.CaptureChunk(end=ip.UploadEnd(upload_id=upload_id))
