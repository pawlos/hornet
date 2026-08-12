#!/usr/bin/env python3
"""Render a source-level coverage report from a cobertura file produced by
scripts/coverage-report.sh. Stdlib only."""
import argparse, os, sys, xml.etree.ElementTree as ET


def parse_cobertura(path):
    """build-path -> {line: hits}. A file can appear under several <class>
    elements (nested types, async state machines); merge them, keeping max hits."""
    out = {}
    for pkg in ET.parse(path).getroot().iter("package"):
        for cls in pkg.iter("class"):
            fn = cls.get("filename") or ""
            if not fn:
                continue
            d = out.setdefault(fn, {})
            for ln in cls.iter("line"):
                n, h = int(ln.get("number")), int(ln.get("hits", "0"))
                d[n] = max(d.get(n, 0), h)
    return out


def file_stats(lines):
    return sum(1 for v in lines.values() if v > 0), len(lines)


# Optional: the report is useful without a campaign, so absence is not an error.
CAMPAIGN_KEYS = ["execs_done", "corpus_count", "edges_found",
                 "saved_crashes", "saved_hangs", "bitmap_cvg"]


def read_fuzzer_stats(path):
    if not path or not os.path.isfile(path):
        return {}
    out = {}
    for line in open(path, encoding="utf-8", errors="replace"):
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k, v = k.strip(), v.strip()
        if k in CAMPAIGN_KEYS:
            out[k] = v
    return out


def self_test():
    failures = []

    def check(name, cond, detail=""):
        if cond:
            print(f"  ok   {name}")
        else:
            print(f"  FAIL {name} {detail}")
            failures.append(name)

    # parse_cobertura must dedupe lines shared by several <class> elements,
    # keeping the highest hit count (a line covered by any class is covered).
    xml = """<coverage><packages><package name="p">
      <classes>
        <class name="A" filename="/_/src/Foo.cs"><lines>
          <line number="1" hits="3"/><line number="2" hits="0"/>
        </lines></class>
        <class name="A/inner" filename="/_/src/Foo.cs"><lines>
          <line number="2" hits="7"/><line number="9" hits="0"/>
        </lines></class>
      </classes></package></packages></coverage>"""
    p = "/tmp/_covtest.xml"
    open(p, "w").write(xml)
    got = parse_cobertura(p)
    os.remove(p)

    check("parse: one file key", list(got) == ["/_/src/Foo.cs"], got)
    check("parse: merges line sets", sorted(got["/_/src/Foo.cs"]) == [1, 2, 9])
    check("parse: keeps max hits", got["/_/src/Foo.cs"][2] == 7)
    check("stats: hit/instrumented", file_stats(got["/_/src/Foo.cs"]) == (2, 3),
          file_stats(got["/_/src/Foo.cs"]))

    p = "/tmp/_covstats.txt"
    open(p, "w").write("execs_done        : 12345\nunrelated : 7\ncorpus_count      : 42\n")
    st = read_fuzzer_stats(p)
    os.remove(p)
    check("stats: picks known keys", st.get("execs_done") == "12345" and st.get("corpus_count") == "42", st)
    check("stats: ignores unknown keys", "unrelated" not in st)
    check("stats: missing file is empty", read_fuzzer_stats("/tmp/_nope_") == {})

    print()
    print("SELF-TEST PASSED" if not failures else f"{len(failures)} SELF-TEST FAILURE(S)")
    return 0 if not failures else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cobertura")
    ap.add_argument("--harness", default="")
    ap.add_argument("--library", default="")
    ap.add_argument("--output")
    ap.add_argument("--inputs-used", type=int, default=0)
    ap.add_argument("--inputs-total", type=int, default=0)
    ap.add_argument("--missing-symbols", default="")
    ap.add_argument("--source-root", default="")
    ap.add_argument("--runtime-tag", default="")
    ap.add_argument("--fuzzer-stats", default="")
    ap.add_argument("--max-files", type=int, default=6)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if not a.cobertura or not a.output:
        ap.error("--cobertura and --output are required")
    cov = parse_cobertura(a.cobertura)
    print(f"parsed {len(cov)} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
