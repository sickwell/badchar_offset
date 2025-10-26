#!/usr/bin/env python3
# badchar_offset.py — MSF-like pattern_create + pattern_offset with -b badchars
import sys, argparse

DEFAULT_SETS = {
    "upper":  "".join(chr(c) for c in range(ord('A'), ord('Z')+1)),
    "lower":  "".join(chr(c) for c in range(ord('a'), ord('z')+1)),
    "number": "".join(chr(c) for c in range(ord('0'), ord('9')+1)),
}

def parse_badchars(s: str) -> set[int]:
    if not s: return set()
    s = s.strip()
    if "\\x" in s:
        hexstr = s.replace("\\x", "").replace(" ", "")
        if len(hexstr) % 2 != 0:
            raise ValueError("Badchars hex string length must be even")
        return set(bytes.fromhex(hexstr))
    return set(s.encode("latin1", errors="ignore"))

def filter_set_chars(s: str, bad: set[int]) -> str:
    if not bad: return s
    return "".join(ch for ch in s if ord(ch) not in bad)

def normalize_sets(user_sets, badchars: set[int]):
    if not user_sets:
        sets = [DEFAULT_SETS["upper"], DEFAULT_SETS["lower"], DEFAULT_SETS["number"]]
    else:
        sets = []
        for tok in user_sets:
            key = tok.strip().lower()
            sets.append(DEFAULT_SETS[key] if key in DEFAULT_SETS else tok)
    sets = [filter_set_chars(s, badchars) for s in sets]
    for i, s in enumerate(sets, 1):
        if not s:
            raise ValueError(f"Character set #{i} became empty after applying badchars")
    if len(sets) == 1:
        sets = [sets[0], sets[0], sets[0]]
    elif len(sets) == 2:
        sets = [sets[0], sets[1], sets[0]]
    return sets

def pattern_create(length: int, sets: list[str]) -> bytes:
    a, b, c = sets[0], sets[1], sets[2]
    out = []
    la, lb, lc = len(a), len(b), len(c)
    ia = ib = ic = 0
    while len(out) < length:
        out.append(a[ia])
        if len(out) >= length: break
        out.append(b[ib])
        if len(out) >= length: break
        out.append(c[ic])
        ic += 1
        if ic >= lc:
            ic = 0
            ib += 1
            if ib >= lb:
                ib = 0
                ia += 1
                if ia >= la:
                    ia = 0
    return "".join(out)[:length].encode("latin1", errors="ignore")

def le32_pack(n: int) -> bytes:
    return bytes((n & 0xff, (n>>8)&0xff, (n>>16)&0xff, (n>>24)&0xff))

def le32_unpack(b4: bytes) -> int:
    return b4[0] | (b4[1]<<8) | (b4[2]<<16) | (b4[3]<<24)

def pattern_offset(buf: bytes, q: int, start: int = 0):
    needle = le32_pack(q)
    idx = buf.find(needle, start)
    return idx if idx != -1 else None

def parse_query_msf(qstr: str) -> int:
    s = qstr.strip()
    if len(s) >= 8:
        try:
            hv = int(s, 16)
            if hv > 0:
                return hv
        except ValueError:
            pass
    if len(s) == 4:
        return le32_unpack(s.encode("latin1", errors="strict"))
    if s.lower().startswith("0x"):
        s = s[2:]
    return int(s, 16)

class _Fmt(argparse.ArgumentDefaultsHelpFormatter, argparse.RawTextHelpFormatter):
    pass

def main():
    examples = (
        "Examples:\n"
        "  # 1) Generate pattern (length 6000)\n"
        "  badchar_offset.py -l 6000 \n\n"
        "  # 2) Generate with badchars filtered out\n"
        r"  badchar_offset.py -l 6000 -b '\x00\x0a\x0d\x20\x25\x2b\x2f\x5c' " "\n\n"
        "  # 3) Find offset later (same length)\n"
        "  badchar_offset.py -l 6000 -q 62433362\n\n"
        "  # 4) Find offset with sets and badchars\n"
        r"  badchar_offset.py -l 2000 -b '\x42\x41' -q 62433362" "\n"
    )

    ap = argparse.ArgumentParser(
        prog="badchar_offset.py",
        usage="%(prog)s -l LENGTH [-q QUERY] [-s SETS] [-b BADCHARS]",
        formatter_class=_Fmt,
        description=(
            "Generate a MSF-compatible pattern (pattern_create) and locate offsets (pattern_offset) with additional -b (badchars) filtering.\n"
            "\n"
            "REQUIRED: -l/--length first; optional -q searches within the generated buffer."
        ),
        epilog=examples,
        add_help=False,          # <<< FIX: disable default -h to avoid conflict
    )

    req = ap.add_argument_group("required arguments")
    req.add_argument("-l", "--length", type=int, required=True,
                     help="The length of the pattern to generate")

    opt = ap.add_argument_group("optional arguments")
    opt.add_argument("-q", "--query", type=str,
                     help="Query to Locate (e.g. Aa0A, 41326141, 0x41326141)")
    opt.add_argument("-s", "--sets",
                     type=lambda s: [t.strip() for t in s.split(",")],
                     help="Custom Pattern Sets (presets: upper,lower,number; or literals: ABC,def,123)")
    opt.add_argument("-b", "--badchars", default="",
                     help=r'Badchars to exclude from sets, e.g. "\x00\x0a\x0d\x20\x25\x2b\x2f\x5c" or raw')
    opt.add_argument("-h", "--help", action="help", help="Show this message and exit")

    args = ap.parse_args()

    try:
        bad = parse_badchars(args.badchars)
        sets = normalize_sets(args.sets, bad)
    except Exception as e:
        print(f"[x] {e}", file=sys.stderr); sys.exit(1)

    buf = pattern_create(args.length, sets)

    if args.query is None:
        try: sys.stdout.buffer.write(buf)
        except BrokenPipeError: pass
        return

    try:
        q = parse_query_msf(args.query)
    except Exception as e:
        print(f"[x] Failed to parse query: {e}", file=sys.stderr); sys.exit(1)

    off = pattern_offset(buf, q)
    if off is None:
        found_any = False
        print("[*] No exact matches, looking for likely candidates...", file=sys.stderr)
        for idx in range(4):
            base = bytearray(le32_pack(q))
            for c in range(256):
                nvb = bytearray(base); nvb[idx] = c
                nvi = le32_unpack(nvb)
                off2 = pattern_offset(buf, nvi)
                if off2 is not None:
                    mle = q - le32_unpack(buf[off2:off2+4])
                    mbe = q - int.from_bytes(buf[off2:off2+4], "big", signed=False)
                    print(f"[+] Possible match at offset {off2} (adjusted [ little-endian: {mle} | big-endian: {mbe} ] ) byte offset {idx}")
                    found_any = True
        if found_any: return
        for idx in (0, 2):
            base = bytearray(le32_pack(q))
            for c in range(65536):
                nvb = bytearray(base)
                nvb[idx:idx+2] = c.to_bytes(2, "little")
                nvi = le32_unpack(nvb)
                off3 = pattern_offset(buf, nvi)
                if off3 is not None:
                    mle = q - le32_unpack(buf[off3:off3+4])
                    mbe = q - int.from_bytes(buf[off3:off3+4], "big", signed=False)
                    print(f"[+] Possible match at offset {off3} (adjusted [ little-endian: {mle} | big-endian: {mbe} ] )")
                    found_any = True
        return

    while off is not None:
        print(f"[*] Exact match at offset {off}")
        off = pattern_offset(buf, q, off + 1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Aborted!")
