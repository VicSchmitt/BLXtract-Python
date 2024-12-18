#!/usr/bin/env python3

"""
Author: Victor Schmitt

This code is based on Robert Graham's adaptation of Dennis Montgomery's 'CExtractor' tool released by Mike Lindell's
Cyber Symposium. This code adapts Robert Graham's C code to extract records from Dennis Montgomery's 'BLX' files
using python.

Robert Graham BLXtract C code GitHub link: https://github.com/robertdavidgraham/blxtract
"""
import os.path
import re
import sys
import mmap
from tqdm import tqdm
from datetime import datetime


def ROT3_left(s):
    """Rotate all bytes in a string by 3 to the left. This is called when
    we find a record and need to "decode" it."""

    return bytes((b - 3) % 256 for b in s)


def ROT3_right(s):
    """Rotate all the bytes in a string by 3 to the right. Called only
    on startup to convert the `record_start_marks` patterns."""

    return bytes((b + 3) % 256 for b in s)


# Strings marking starts of records
record_start_marks = [
    b"xT1y22", b"tx16!!", b"eTreppid1!", b"shaitan123"
]
start_mark_len = [len(s) for s in record_start_marks]
is_first = None
# Precompile with regex
rotated_patterns = [re.escape(ROT3_right(s)) for s in record_start_marks]
combined_pattern = b'|'.join(rotated_patterns)
pattern = re.compile(combined_pattern)


def delim_end(buf, delim):
    """Searches the buffer for the pattern, returning the number of bytes up
    to the start of that pattern."""

    index = buf.find(delim)
    return index


def delim_search(buf, offset, remaining, mask):
    match = pattern.search(buf, offset)
    if match:
        return match.end(), True
    else:
        return remaining, False


def extract_files(filename, out, mask, show_progress=False):
    """Given a filename, search through all the records and print the results."""
    i = 0
    total_offset = 0
    BUFSIZE = 16 * 1024 * 1024
    buf_size = BUFSIZE + 4096  # Extra space for sentinel

    try:
        fp = open(filename, 'rb')
        file_size = os.path.getsize(filename)
    except IOError as e:
        print(f"[-] {filename}:open: {e}", file=sys.stderr)
        return 1

    print(f"[-] {filename}: opened [pass:{mask:x}]", file=sys.stderr)

    # Progress bar init
    if show_progress:
        progress_bar = tqdm(total=file_size, unit='B', unit_scale=True, desc=filename)
    else:
        progress_bar = None

    # Preallocate the buffer with zero bytes
    buf = bytearray(buf_size)
    remaining = 0

    while True:
        # If the remaining data in the buffer isn't long enough, read more data
        if i + 16 + 1024 > remaining:
            # Move the remaining bytes to the front
            remaining_bytes = remaining - i
            buf[:remaining_bytes] = buf[i:remaining]
            total_offset += i
            remaining = remaining_bytes
            i = 0

            # Read more data into the buffer
            bytes_to_read = BUFSIZE - remaining
            bytes_read = fp.read(bytes_to_read)
            if not bytes_read:
                break
            read_len = len(bytes_read)
            buf[remaining:remaining + read_len] = bytes_read
            remaining += read_len

            if show_progress:
                progress_bar.update(read_len)

            if remaining < 10 + 1024:
                break

            # Place a sentinel byte (same as C code)
            buf[remaining] = record_start_marks[0][0]
        else:
            remaining_bytes = remaining

        # Search for start-of-record delimiter
        new_i, found = delim_search(buf, i, remaining, mask)

        # If we've reached the end of the buffer without finding a pattern, loop back
        if remaining - new_i < 10 + 1024:
            i = new_i
            continue

        if not found:
            i = new_i
            continue

        # At this point, a delimiter was found, and 'i' points just after it
        i = new_i

        # Rotate the bytes
        record = ROT3_left(buf[i:i + 1024])

        # Search for end-of-record delimiter
        record_length = delim_end(record, b'.dev@7964')

        if record_length == -1:
            i += 1  # Advance the index to avoid infinite loop
            continue

        # Write the output
        out.write(record[:record_length] + b'\r\n')
        i += 1024  # Move index past this record

    fp.close()
    if show_progress:
        progress_bar.close()

    print(f"[+] {filename}: processed", file=sys.stderr)
    return 0


def delim_initialize():
    """The file-format works by having a 'delimiter' at the start of each record.
    We search forward to find those delimiters. We want to optimize this search
    a bit with static tables. We could just hard-code these values,
    but we initialize them programmatically instead to document what they are
    doing."""

    global record_start_marks, is_first, start_mark_len

    # Rotate the record start patterns
    record_start_marks = [ROT3_right(s) for s in record_start_marks]

    start_mark_len = [len(s) for s in record_start_marks]

    # Create a lookup table for the first byte of each pattern
    is_first = [0] * 256
    for s in record_start_marks:
        is_first[s[0]] = 1


def main():
    argv = sys.argv
    argc = len(argv)
    # Error code
    err = 0
    is_ordered = False
    show_progress = False

    # Help menu
    if argc <= 1 or argv[1] in ('-h', '--help'):
        print("usage:\n python3 blxtract.py <filename> [<filename> ...]", file=sys.stderr)
        sys.exit(-1)

    # Initialize delimiters
    delim_initialize()

    curr_time = datetime.now().strftime("%H:%M:%S")
    print(f"[-] Start time is {curr_time}", file=sys.stderr)

    # Process all files specified in arguments
    print(f"[-] blxtract (python adaptation) - extracting files", file=sys.stderr)
    out = sys.stdout.buffer

    for arg in argv[1:]:
        if arg == '--ordered':
            is_ordered = True
            continue

        if arg == '--progress':
            show_progress = True
            continue

        if is_ordered:
            err += extract_files(arg, out, 0x01, show_progress)
            err += extract_files(arg, out, 0x02, show_progress)
            err += extract_files(arg, out, 0x04, show_progress)
            err += extract_files(arg, out, 0x08, show_progress)
        else:
            err += extract_files(arg, out, 0xFF, show_progress)

    curr_time = datetime.now().strftime("%H:%M:%S")
    print(f"[+] End time is {curr_time}", file=sys.stderr)
    sys.exit(err)


if __name__ == '__main__':
    main()
