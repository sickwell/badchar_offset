# badchar_offset.py
MSF-style pattern + offset finder with **-b** badchar filtering.

Generate with `-l` (optionally `-s`, `-b`), then locate with `-q` using the same options.

```bash
# generate (no badchars)
python3 badchar_offset.py -l 2000
# [*] Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3A...

# generate with badchars
python3 badchar_offset.py -l 2000 -b "\x42\x41"
# [*] Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3C...

# locate offset (same length as generated)
python3 badchar_offset.py -l 2000 -q 62433362
# [*] Exact match at offset 40

# locate with badchars
python3 badchar_offset.py -l 2000 -b "\x42\x41" -q 62433362
# [*] Exact match at offset 40
```
