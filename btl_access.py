#!/usr/bin/env python3.11
"""
Extract register accesses from one or more btl monitor logs.

Each access is printed as:
<req_ts> <READ|WRITE> <interface> addr=<address> [data=<hex>[,<hex>...]]
  <rsp_ts> RESPONSE <fields...>

Assumptions:
  - btl2txt tool is available in PATH or passed via --btl2txt argument or BTL2TXT env.
  - Monitor line formats resemble:
        627189: MI0_AID0_MP5_SCF_SmnIniu_mon.raddr_mon addr:0x000002f3fd08 ... rid:0x000370 ...
        627243: MI0_AID0_MP5_SCF_SmnIniu_mon.rrsp_mon rid:0x000370 rresp:OKAY rlast:1 rdata:0x00000000
        627433: MI0_AID0_MP5_SCF_SmnIniu_mon.waddr_mon addr:0x000002f3fd08 ... wid:0x000370 ...
        627434: MI0_AID0_MP5_SCF_SmnIniu_mon.wdata_mon wlast:1 wstrb:0xf wdata:0x00000010
        627487: MI0_AID0_MP5_SCF_SmnIniu_mon.wrsp_mon bid:0x000370 bresp:OKAY

"""
from __future__ import annotations
import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

# Default command (override via --btl2txt or BTL2TXT env)
DEFAULT_BTL2TXT = os.environ.get("BTL2TXT", "btl2txt")

# Regex to parse a generic monitor line
LINE_RE = re.compile(r"""
    ^\s*(?P<ts>\d+):\s+
    (?P<iface>[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*?)\.
    (?P<stream>(?:raddr_mon|rrsp_mon|waddr_mon|wdata_mon|wrsp_mon))\s+
    (?P<rest>.*)$
""", re.VERBOSE)

ADDR_RE = re.compile(r"addr:(0x[0-9A-Fa-f]+)")
RID_RE = re.compile(r"rid:(0x[0-9A-Fa-f]+)")
WID_RE = re.compile(r"wid:(0x[0-9A-Fa-f]+)")
BID_RE = re.compile(r"bid:(0x[0-9A-Fa-f]+)")
RDATA_RE = re.compile(r"rdata:(0x[0-9A-Fa-f]+)")
WDATA_RE = re.compile(r"wdata:(0x[0-9A-Fa-f]+)")
RLAST_RE = re.compile(r"rlast:(\d)")
WLAST_RE = re.compile(r"wlast:(\d)")
RRESP_RE = re.compile(r"rresp:([A-Za-z0-9_]+)")
BRESP_RE = re.compile(r"bresp:([A-Za-z0-9_]+)")

@dataclass
class AccessRecord:
    kind: str                  # "READ" or "WRITE"
    interface: str
    address: str
    req_ts: int
    txn_id: str                # rid/wid (hex string)
    write_data: List[str] = field(default_factory=list)
    read_data: List[str] = field(default_factory=list)
    rsp_ts: Optional[int] = None
    rsp_status: Optional[str] = None
    complete: bool = False


def run_btl2txt(btl2txt_cmd: str, path: str) -> List[str]:
    """Run btl2txt on a file and return list of text lines.

    Workaround: btl2txt must be invoked from the directory containing the .btl file
    and passed a relative path (filename only) due to an internal path resolution bug.
    """
    directory = os.path.dirname(path) or '.'
    filename = os.path.basename(path)
    try:
        result = subprocess.run(
            [btl2txt_cmd, filename],
            check=True,
            cwd=directory,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"ERROR: btl2txt failed for {path}: {e.stderr.strip()}", file=sys.stderr)
        return []
    return result.stdout.splitlines()


def parse_line(line: str):
    m = LINE_RE.match(line)
    if not m:
        return None
    return {
        "ts": int(m.group("ts")),
        "iface": m.group("iface"),
        "stream": m.group("stream"),
        "rest": m.group("rest"),
        "raw": line,
    }


def extract(field_re: re.Pattern, text: str) -> Optional[str]:
    m = field_re.search(text)
    return m.group(1) if m else None


def process_ordered(parsed_lines: List[Dict[str, object]],
                    completed: List[AccessRecord],
                    pending_reads: Dict[str, Dict[str, List[AccessRecord]]],
                    pending_writes: Dict[str, Dict[str, List[AccessRecord]]]) -> None:
    """Process parsed & globally time-ordered lines.

    Pending structures are indexed first by interface then by transaction ID to avoid ID collisions across interfaces.

    For each (iface, ID) maintain a FIFO list (queue) of outstanding transactions:
      - raddr_mon / waddr_mon pushes a fresh record into pending_reads[iface][rid] or pending_writes[iface][wid].
      - rrsp_mon consumes head of pending_reads[iface][rid] when rlast=1 (appending intermediate rdata before final).
      - wdata_mon appends to the most recent (largest req_ts) incomplete WRITE on that interface only.
      - wrsp_mon finalizes and pops the head of pending_writes[iface][bid].
    """
    for parsed in parsed_lines:
        ts   = parsed['ts']
        iface = parsed['iface']
        stream = parsed['stream']
        rest = parsed['rest']

        if stream == 'raddr_mon':
            rid = extract(RID_RE, rest)
            addr = extract(ADDR_RE, rest)
            if rid and addr:
                rec = AccessRecord(kind='READ', interface=iface, address=addr, req_ts=ts, txn_id=rid)
                pending_reads.setdefault(iface, {}).setdefault(rid, []).append(rec)

        elif stream == 'rrsp_mon':
            rid = extract(RID_RE, rest)
            if not rid or iface not in pending_reads or rid not in pending_reads[iface] or not pending_reads[iface][rid]:
                continue  # orphan response
            rec = pending_reads[iface][rid][0]
            rdata = extract(RDATA_RE, rest)
            rresp = extract(RRESP_RE, rest)
            rlast = extract(RLAST_RE, rest)
            if rdata:
                rec.read_data.append(rdata)
            if rlast == '1':
                rec.rsp_ts = ts
                rec.rsp_status = rresp or 'UNKNOWN'
                rec.complete = True
                completed.append(rec)
                pending_reads[iface][rid].pop(0)
                if not pending_reads[iface][rid]:
                    del pending_reads[iface][rid]
                if not pending_reads[iface]:
                    del pending_reads[iface]

        elif stream == 'waddr_mon':
            wid = extract(WID_RE, rest)
            addr = extract(ADDR_RE, rest)
            if wid and addr:
                rec = AccessRecord(kind='WRITE', interface=iface, address=addr, req_ts=ts, txn_id=wid)
                pending_writes.setdefault(iface, {}).setdefault(wid, []).append(rec)

        elif stream == 'wdata_mon':
            wdata = extract(WDATA_RE, rest)
            if not wdata or iface not in pending_writes:
                continue
            # Choose latest incomplete write on this interface only.
            candidate: Optional[AccessRecord] = None
            latest_ts = -1
            for wid_queue in pending_writes[iface].values():
                if not wid_queue:
                    continue
                # Active record is last element in wid_queue until response.
                last_rec = wid_queue[-1]
                if (not last_rec.complete) and last_rec.req_ts > latest_ts:
                    candidate = last_rec
                    latest_ts = last_rec.req_ts
            if candidate:
                candidate.write_data.append(wdata)

        elif stream == 'wrsp_mon':
            bid = extract(BID_RE, rest)
            bresp = extract(BRESP_RE, rest)
            if not bid or iface not in pending_writes or bid not in pending_writes[iface] or not pending_writes[iface][bid]:
                continue
            rec = pending_writes[iface][bid][0]
            rec.rsp_ts = ts
            rec.rsp_status = bresp or 'UNKNOWN'
            rec.complete = True
            completed.append(rec)
            pending_writes[iface][bid].pop(0)
            if not pending_writes[iface][bid]:
                del pending_writes[iface][bid]
            if not pending_writes[iface]:
                del pending_writes[iface]


def format_record(rec: AccessRecord, iface_w: int, addr_w: int, ts_w: int) -> List[str]:
    """Format a record with padded columns.

    Columns aligned:
      req_ts (right), kind (left, width 5), interface (left, iface_w), addr value (left, addr_w)
    """
    req_head = f"{rec.req_ts:>{ts_w}} {rec.kind:<5} {rec.interface:<{iface_w}} addr={rec.address:<{addr_w}}"
    tail_bits: List[str] = []
    if rec.kind == "WRITE" and rec.write_data:
        if len(rec.write_data) == 1:
            tail_bits.append(f"data={rec.write_data[0]}")
        else:
            tail_bits.append("data=[" + ",".join(rec.write_data) + "]")
    req_line = req_head + (" " + " ".join(tail_bits) if tail_bits else "")

    lines = [req_line]

    if rec.rsp_ts is not None:
        rsp_head = f"{rec.rsp_ts:>{ts_w}} RESPONSE status={rec.rsp_status}"  # no column alignment requested for response
        rsp_tail: List[str] = []
        if rec.kind == "READ" and rec.read_data:
            if len(rec.read_data) == 1:
                rsp_tail.append(f"rdata={rec.read_data[0]}")
            else:
                rsp_tail.append("rdata=[" + ",".join(rec.read_data) + "]")
        lines.append("  " + rsp_head + (" " + " ".join(rsp_tail) if rsp_tail else ""))
    else:
        lines.append("  (response pending)")

    return lines


def main():
    parser = argparse.ArgumentParser(description="Extract register accesses from btl monitor files.")
    parser.add_argument("btl_files", nargs="+", help="Input .btl files")
    parser.add_argument("--btl2txt", default=DEFAULT_BTL2TXT,
                        help="Path to btl2txt executable (default: BTL2TXT env or 'btl2txt')")
    parser.add_argument("--show-incomplete", action="store_true", help="Include requests without responses")
    args = parser.parse_args()

    # Collect & parse all lines first, then globally order
    parsed_lines: List[Dict[str, object]] = []
    for path in args.btl_files:
        if not os.path.isfile(path):
            print(f"WARNING: Skipping missing file {path}", file=sys.stderr)
            continue
        if path[-4:] == ".btl":
            src = run_btl2txt(args.btl2txt, path)
        else:
            f = open(path)
            src = f.readlines()
        for raw in src:
            p = parse_line(raw)
            if p:
                parsed_lines.append(p)

    parsed_lines.sort(key=lambda d: d['ts'])

    completed: List[AccessRecord] = []
    # Indexed by interface -> ID -> queue[list] of AccessRecord
    pending_reads: Dict[str, Dict[str, List[AccessRecord]]] = {}
    pending_writes: Dict[str, Dict[str, List[AccessRecord]]] = {}

    process_ordered(parsed_lines, completed, pending_reads, pending_writes)

    output_records: List[AccessRecord] = list(completed)
    if args.show_incomplete:
        # Flatten nested queues
        for iface_map in pending_reads.values():
            for q in iface_map.values():
                output_records.extend(q)
        for iface_map in pending_writes.values():
            for q in iface_map.values():
                output_records.extend(q)

    output_records.sort(key=lambda r: r.req_ts)

    # Compute column widths for alignment
    iface_w = max((len(r.interface) for r in output_records), default=8)
    addr_w = max((len(r.address) for r in output_records), default=10)
    ts_w = max(len(str(r.req_ts)) for r in output_records) if output_records else 1

    for rec in output_records:
        for line in format_record(rec, iface_w=iface_w, addr_w=addr_w, ts_w=ts_w):
            print(line)

if __name__ == "__main__":
    main()
