import argparse
import os
import math
import mmap
import time
from enum import Enum, auto
from minidump.minidumpfile import MinidumpFile
from yaspin import yaspin

# Configure this as you wish
MIN_NULL_START_REGION_SIZE = 10_000
MIN_NULL_END_REGION_SIZE = 10_000
MAX_REGION_SIZE = 2 * 1024 * 1024
AVERAGE_REGION_SIZE = 100_000
MIN_REGION_SIZE = 25_000
AES_KEY_SIZE = 32
LOOKAHEAD = 300
AES_ENTROPY_THRESHOLD = 4.7
REQUIRED_REPEATS = 10
MAX_INITIAL_SCAN_IN_REGION = 500
PRE_NULL_CHECK = 64

NULL_BLOCK_START = b"\x00" * MIN_NULL_START_REGION_SIZE
NULL_BLOCK_END = b"\x00" * MIN_NULL_END_REGION_SIZE


class ScanMode(Enum):
    Forward = auto()
    Backward = auto()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0
    for f in freq:
        if f:
            p = f / len(data)
            entropy -= p * math.log2(p)
    return entropy


def find_regions_from_minidump(file_path: str):
    start_time = time.time()
    dump = MinidumpFile.parse(file_path)

    regions = []

    if dump.memory_segments_64:
        for seg in dump.memory_segments_64.memory_segments:
            size = seg.size
            file_offset = seg.start_file_address

            if MIN_REGION_SIZE < size <= MAX_REGION_SIZE:
                regions.append((file_offset, file_offset + size, size))

    elapsed = time.time() - start_time
    return regions, elapsed


def find_regions_loose(file_path: str, scan_mode: ScanMode):
    """
    Alternative dumb method if minidump is corrupted
    Finds regions sorrounded by large null chunks
    """
    size = os.path.getsize(file_path)
    regions = []
    start_time = time.time()

    with open(file_path, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        pos = 0

        if scan_mode == ScanMode.Forward:
            while pos < size:
                start_null = mm.find(NULL_BLOCK_START, pos)
                if start_null == -1:
                    break

                region_start = start_null + MIN_NULL_START_REGION_SIZE

                next_non_null = mm.find(b"\x01", region_start)
                if next_non_null == -1:
                    break
                region_start = next_non_null

                if region_start >= size:
                    break

                end_null = mm.find(NULL_BLOCK_END, region_start)
                if end_null == -1:
                    break

                region_end = end_null

                region_size = region_end - region_start
                if MIN_REGION_SIZE < region_size <= MAX_REGION_SIZE:
                    regions.append((region_start, region_end, region_size))

                pos = end_null + MIN_NULL_START_REGION_SIZE
        elif scan_mode == ScanMode.Backward:
            pos = 0
            while pos < size:
                end_null = mm.find(NULL_BLOCK_END, pos)
                if end_null == -1:
                    break

                region_end = end_null

                region_start = max(0, region_end - AVERAGE_REGION_SIZE)
                region_size = region_end - region_start

                check_start = max(region_start, region_end - PRE_NULL_CHECK)
                if mm[check_start:region_end].count(0) == (region_end - check_start):
                    pos = end_null + MIN_NULL_END_REGION_SIZE
                    continue

                if region_size >= MIN_REGION_SIZE:
                    regions.append((region_start, region_end, region_size))

                pos = end_null + MIN_NULL_END_REGION_SIZE

    mm.close()

    elapsed = time.time() - start_time
    return regions, elapsed


def find_aes_keys_in_regions(file_path, regions):
    keys_found = set()
    start_time = time.time()

    with open(file_path, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        for region_start, region_end, region_size in regions:
            initial_end = min(region_start + MAX_INITIAL_SCAN_IN_REGION,
                              region_end - AES_KEY_SIZE)

            i = region_start

            while i < initial_end and mm[i] == 0x00:
                i += 1

            while i <= initial_end - AES_KEY_SIZE:
                candidate = mm[i:i + AES_KEY_SIZE]

                # NOTE:
                # It's possible for AES key to start with null bytes
                # So in case if key was found, and it isn't working, just try adding null bytes back
                if candidate[0] == 0x00:
                    i += 1
                    continue
                if candidate.count(b"\x00") > 2:
                    i += 1
                    continue
                if i - 2 < region_start or mm[i - 2:i] != b"\x00\x00":
                    i += 1
                    continue

                entropy = shannon_entropy(candidate)
                if entropy >= AES_ENTROPY_THRESHOLD:
                    repeat_count = 1
                    scan_pos = i
                    while repeat_count < REQUIRED_REPEATS:
                        lookahead_start = scan_pos + 1
                        lookahead_end = min(region_end - AES_KEY_SIZE, scan_pos + LOOKAHEAD)

                        found_next = False
                        for j in range(lookahead_start, lookahead_end):
                            if mm[j:j + AES_KEY_SIZE] == candidate:
                                repeat_count += 1
                                scan_pos = j
                                found_next = True
                                break

                        if not found_next:
                            break

                    if repeat_count >= REQUIRED_REPEATS:
                        keys_found.add(candidate)

                i += 1

        mm.close()

    elapsed = time.time() - start_time
    return keys_found, elapsed


def main():
    parser = argparse.ArgumentParser(
        description="Scan a memory dump for AES keys",
        epilog="Example: python aes_dump.py path_to_dump.dmp"
    )
    parser.add_argument("dmp_file_path", type=str, help="Path to memory dump file")
    args = parser.parse_args()

    file_path = args.dmp_file_path
    if not os.path.isfile(file_path):
        print(f"Error: File not found: {file_path}")
        parser.print_usage()
        return

    scan_steps = [
        (find_regions_from_minidump, None, "Minidump Scan"),
        (find_regions_loose, ScanMode.Forward, "Loose Scan Forward"),
        (find_regions_loose, ScanMode.Backward, "Loose scan Backward"),
    ]

    print()
    print(os.path.basename(file_path))

    keys = []
    for scan_func, mode, description in scan_steps:
        with yaspin(text=f"Scanning regions ({description})..") as sp:
            regions, elapsed = scan_func(file_path) if mode is None else scan_func(file_path, mode)

            if not regions:
                sp.text = " " * 80
                sp.fail("✖ No memory regions found in minidump")
                continue

            sp.ok("✔")

        print(f"➤ Found {len(regions)} regions in {elapsed:.2f}s")

        with yaspin(text="Searching for AES keys in regions..") as sp:
            keys, elapsed = find_aes_keys_in_regions(file_path, regions)

            if keys:
                sp.ok("✔")
                sp.write(f"➤ Found {len(keys)} AES key(s) in {elapsed:.2f}s")
                break
            else:
                sp.text = " " * 80
                sp.fail("✖ No keys found in these regions")

    if not keys:
        print("No AES keys were found :(")
        return

    print("\n=== POSSIBLE AES KEY(S) FOUND ===")
    for k in keys:
        print(f"0x{k.hex().upper()}")


if __name__ == "__main__":
    main()
