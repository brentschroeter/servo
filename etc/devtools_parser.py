#!/usr/bin/env python3

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# This is a script designed to easily debug devtools messages
# It takes the content of a pcap wireshark capture (or creates a new
# one when using `-w`) and prints the JSON payloads.
#
# Wireshark (more specifically its cli tool tshark) needs to be installed
# for this script to work. Go to https://tshark.dev/setup/install for a
# comprehensive guide on how to install it. In short:
#
# Linux (Debian based):       apt install tshark
# Linux (Arch based):         pacman -Sy wireshark-cli
# MacOS (With homebrew):      brew install --cask wireshark
# Windows (With chocolatey):  choco install wireshark
#
# To use it, launch Servo or Firefox in devtools mode:
#
# Servo: ./mach run --devtools 6080
# Firefox: firefox --new-instance --start-debugger-server 6080 --profile PROFILE
#
# Then run this tool in capture mode, specifying the same port as before:
#
# ./devtools_parser.py -w capture.pcap -p 6080
#
# Finally, open another instance of Firefox, go to about:debugging and connect
# to localhost:6080. Messages should start popping up. The scan can be finished
# by pressing Ctrl+C.
#
# To review the results of the scan use the `-r` flag. It is possible to output
# newline-delimited JSON for further processing with other tools using the
# `--json` flag.
#
# ./devtools_parser.py -r capture.pcap --json > capture.json

import json
import os
import pty
import re
import signal
import sys
from argparse import ArgumentParser
from subprocess import Popen

try:
    from termcolor import colored
except ImportError:
    print("[WARNING] Module 'termcolor' not found; falling back to plain output.", file=sys.stderr)

    def colored(text, *args, **kwargs):
        return text


def start_tshark(capture_port, read_file=None, write_file=None, forward_signal=None):
    """Run tshark, either to start a capture or to read an already existing pcap file.
    Returns a tuple of the subprocess `Popen` object and a file descriptor for the piped stdout.
    If the subprocess does not exit of its own accord, remember to explicitly kill it before exiting the parent process."""

    assert read_file is None or write_file is None, "read_file and write_file are mutually exclusive"

    tshark_cmd = [
        "tshark",
        "-Tfields",
        "-eframe.time",
        "-etcp.srcport",
        "-etcp.dstport",
        "-etcp.payload",
    ]
    if args.read_file:
        tshark_cmd += [f"-r{read_file}"]
    else:
        tshark_cmd += ["-ilo", f"-ftcp port {capture_port}"]
    if args.write_file:
        tshark_cmd += [f"-w{write_file}"]
    # Pipe tshark output through a pseudoterminal to prevent buffering.
    tty_out, tty_in = pty.openpty()
    tshark_proc = Popen(tshark_cmd, stdout=tty_in)
    try:
        # tty_out will yield an EOF once both processes have closed tty_in.
        os.close(tty_in)
        if forward_signal is not None:
            # Shutting down tshark will end the loop in process_stream().
            signal.signal(forward_signal, lambda _signal, _frame: tshark_proc.send_signal(forward_signal))
        return tshark_proc, tty_out
    except Exception as e:
        # On any exception between spawning the subprocess and returning it to the caller,
        # kill it to ensure it doesn't continue running outside of our control.
        tshark_proc.kill()
        raise e


def take_first_message(buffered_bytes):
    """Given a sequence of over-the-wire bytes, parse the first devtools protocol message, if present.
    Returns a tuple of the message as decoded JSON (or None if no complete message),
    as well as the remaining unconsumed bytes."""

    def recover_misaligned_buffer():
        # Attempt to realign scan by finding a message boundary.
        # Make sure to match on an expression that cannot be wrapped within a valid JSON message payload.
        # (This assumes that top-level keys don't start with colons, commas, or closing brackets.)
        next_message_header = re.search(rb'}[0-9]+:{\s*"\s*[^,:}\]]', buffered_bytes)
        if next_message_header is not None:
            discarded_bytes = buffered_bytes[: next_message_header.start() + 1]
            print(
                f"[WARNING] Misaligned. Discarding: {repr(discarded_bytes)}",
                file=sys.stderr,
            )
            return take_first_message(buffered_bytes[next_message_header.start() + 1 :])
        return None, buffered_bytes

    # Message records are of the form `length:{...}`, where `length` is an integer in ASCII decimal.
    buffered_parts = buffered_bytes.split(b":", 1)
    if len(buffered_parts) != 2:
        # Message not yet fully buffered.
        return None, buffered_bytes
    maybe_header, rest = buffered_parts
    try:
        message_len = int(maybe_header)
    except ValueError:
        print("[WARNING] Failed to decode message length.")
        # What we thought was the message length must be a fragment of a previous message instead.
        return recover_misaligned_buffer()

    if len(rest) < message_len:
        # Message not yet fully buffered.
        return None, buffered_bytes

    try:
        message_str = rest[:message_len].decode()
    except UnicodeError as e:
        print(f"[WARNING] Failed to decode message as UTF-8: {e}", file=sys.stderr)
        return take_first_message(rest[message_len:])
    try:
        message_json = json.loads(message_str)
    except json.decoder.JSONDecodeError:
        print("[WARNING] Failed to decode message as JSON.", file=sys.stderr)
        # What we thought was the message length must have been something else.
        return recover_misaligned_buffer()

    # Pop first message from the buffer and preserve the rest for next iteration.
    return message_json, rest[message_len:]


def process_tshark_capture(tshark_out):
    """Convert the raw output of tshark into an iterator or devtools messages.
    `tshark_out` expects a file-like reader that iterates over lines as decoded strings.
    We assume that only traffic to/from the relevant port is included.
    Yields (`time`, `src_port`, `dst_port`, `json_data`) for each message."""

    # Buffers (one per sender) for aggregating messages across TCP packets.
    # Bytes are appended to the end until a complete message is present.
    # Bytes comprising each message are removed as the message is processed.
    buffered_bytes = {}
    # Loop until tshark process exits.
    for line in tshark_out:
        line = line.strip("\n")
        if line == "":
            continue
        try:
            time, src_port, dst_port, hex_data = line.split("\t")
        except ValueError:
            print(f"[WARNING] Failed to parse tshark entry: {repr(line)}", file=sys.stderr)
            continue
        assert src_port != dst_port, "src and dst ports cannot be the same on loopback interface"
        if len(hex_data) == 0:
            continue
        if len(hex_data) % 2 == 1:
            print(f"[WARNING] Extra byte in hex-encoded data: {hex_data[-1]}", file=sys.stderr)
            hex_data = hex_data[:-1]
        if src_port not in buffered_bytes:
            buffered_bytes[src_port] = b""
        buffered_bytes[src_port] += bytearray.fromhex(hex_data)
        while True:
            message_json, buffered_bytes[src_port] = take_first_message(buffered_bytes[src_port])
            if message_json is None:
                # Message not yet fully buffered.
                break
            yield time, src_port, dst_port, message_json


def print_message(message_json, time, client_port, i, print_format="plain"):
    """Pretty print the JSON message, actor and timestamp.
    If `print_format` is "json" or "json_with_metadata", output the JSON message in one line instead."""

    assert print_format in ("json", "json_with_metadata", "plain")

    if print_format.startswith("json"):
        # Place from and to at the start so that it is easier to see which actor is involved
        sorted_content = dict(
            sorted(message_json.items(), key=lambda k: f"_{k[0]}" if k[0] == "from" or k[0] == "to" else k[0])
        )
        print(
            json.dumps(
                {"time": time, "client_port": int(client_port), "data": sorted_content} if print_format == "json_with_metadata" else sorted_content
            )
        )
        return

    is_server = "from" in message_json
    colored_sender = (
        colored("Server", "black", "on_yellow") if is_server else colored("Client", "on_magenta", attrs=["bold"])
    )
    pretty_json = json.dumps(message_json, sort_keys=True, indent=4)

    print(f"""
{colored_sender} - {colored(i, "blue")} - {colored(time, "dark_grey")}
{pretty_json}
""")


if __name__ == "__main__":
    # Program arguments
    parser = ArgumentParser()
    parser.add_argument("-p", "--port", default="6080", help="the port where the devtools client is running")
    parser.add_argument("--json", action="store_true", help="output in newline-delimited JSON (NDJSON)")
    parser.add_argument("--metadata", action="store_true", help="include client port and timestamp in NDJSON output")

    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("-w", "--write-file", help="write tshark capture data the output to a .pcap file")
    actions.add_argument("-r", "--read-file", help="parse messages from a .pcap file instead of capturing live")

    args = parser.parse_args()

    if args.json:
        print_format = "json_with_metadata" if args.metadata else "json"
    else:
        print_format = "plain"

    tshark_proc, tty_out = start_tshark(args.port, args.read_file, args.write_file, signal.SIGINT)

    try:
        with open(tty_out) as f:
            for i, (time, src_port, dst_port, message_json) in enumerate(process_tshark_capture(f)):
                client_port = dst_port if src_port == args.port else src_port
                print_message(message_json, time, client_port, i, print_format)
    except Exception as e:
        # Something other than an EOF caused execution to stop, so tshark is likely still running.
        tshark_proc.kill()
        raise e
