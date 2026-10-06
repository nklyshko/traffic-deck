"""The pcap reader thread must not sit on a partial buffer.

A quiet capture produces a few KB a minute, so reading in 64 KiB blocks means the gateway
gets nothing for minutes: a request shows in the viewer with its duration counting up and
its response arriving only when the capture stops. `-U` on the sniffer does not help, it
flushes into the pipe this thread then blocks on.
"""

import queue
import subprocess
import threading
import time

from capture_sdk.livecapture import _reader_thread


def test_bytes_reach_the_queue_before_the_sniffer_exits():
    # A sniffer emitting far less than one 64 KiB block, flushing each write.
    src = ("import sys,time\n"
           "for _ in range(50):\n"
           "    sys.stdout.buffer.write(b'x' * 100); sys.stdout.buffer.flush()\n"
           "    time.sleep(0.02)\n"
           "time.sleep(30)\n")
    p = subprocess.Popen(["python3", "-c", src], stdout=subprocess.PIPE)
    q: queue.Queue = queue.Queue()
    stop = threading.Event()
    t = threading.Thread(target=_reader_thread, args=(p.stdout, q, stop), daemon=True)
    t.start()
    try:
        kind, b = q.get(timeout=5)   # still running: must not wait for EOF or a full block
        assert kind == "pcap"
        assert 0 < len(b) < 65536
    finally:
        stop.set()
        p.kill()
        p.wait()


def test_a_long_read_is_not_cut_short():
    # The other half of the contract: plenty available is still handed over in one go.
    src = "import sys,time\nsys.stdout.buffer.write(b'y' * 40000); sys.stdout.buffer.flush()\ntime.sleep(30)\n"
    p = subprocess.Popen(["python3", "-c", src], stdout=subprocess.PIPE)
    q: queue.Queue = queue.Queue()
    stop = threading.Event()
    t = threading.Thread(target=_reader_thread, args=(p.stdout, q, stop), daemon=True)
    t.start()
    try:
        time.sleep(0.5)
        got = b""
        while not q.empty():
            got += q.get_nowait()[1]
        assert got == b"y" * 40000
    finally:
        stop.set()
        p.kill()
        p.wait()
