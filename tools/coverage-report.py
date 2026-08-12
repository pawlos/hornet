#!/usr/bin/env python3
"""Render a source-level coverage report from a cobertura file produced by
scripts/coverage-report.sh. Stdlib only."""
import argparse, json, os, sys, urllib.request, xml.etree.ElementTree as ET


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


# external/ clones drift from the packaged version. Annotated source rendered
# against drifted source highlights the wrong lines while looking entirely
# normal, which is worse than showing no source at all.
NON_STATEMENT_LIMIT = 0.10


def check_alignment(src_lines, lines):
    if not lines:
        return False, "no instrumented lines"
    hi = max(lines)
    if hi > len(src_lines):
        return False, f"coverage line {hi} is beyond end of file ({len(src_lines)} lines)"
    # Only blank lines and comments are counted: a closing brace IS a sequence
    # point in C# (it is where the method returns), so braces are legitimately
    # instrumented and treating them as suspicious rejects correct source.
    bad = 0
    for n in lines:
        t = src_lines[n - 1].strip()
        if t == "" or t.startswith("//"):
            bad += 1
    frac = bad / len(lines)
    if frac > NON_STATEMENT_LIMIT:
        return False, f"{100 * frac:.0f}% of instrumented lines are blank or comment"
    return True, ""


_SOURCE_CACHE = {}
# How each file's source was obtained. A local clone is not guaranteed to match
# the packaged version, so the report says so rather than implying it does.
_SOURCE_PROVENANCE = {}


def resolve_source(build_path, root_dir, source_root="", runtime_tag=""):
    """Resolve a SourceLink build path such as
    /_/src/runtime/src/libraries/.../Foo.cs to the file's lines, or None."""
    if build_path in _SOURCE_CACHE:
        return _SOURCE_CACHE[build_path]
    rel = build_path.lstrip("/")
    if rel.startswith("_/"):
        rel = rel[2:]

    cands = []
    if source_root:
        cands.append(os.path.join(source_root, rel))
    # dotnet/runtime paths carry a leading src/runtime/ that the clone does not have.
    runtime_rel = rel[len("src/runtime/"):] if rel.startswith("src/runtime/") else None
    ext = os.path.join(root_dir, "external")
    if os.path.isdir(ext):
        for clone in sorted(os.listdir(ext)):
            cands.append(os.path.join(ext, clone, rel))
            if runtime_rel:
                cands.append(os.path.join(ext, clone, runtime_rel))

    for c in cands:
        if os.path.isfile(c):
            _SOURCE_CACHE[build_path] = open(c, encoding="utf-8", errors="replace").read().split("\n")
            _SOURCE_PROVENANCE[build_path] = "local"
            return _SOURCE_CACHE[build_path]

    # GitHub at a tag, dotnet/runtime only — the commit SHA embedded in assembly
    # version strings is an internal build commit that does not resolve publicly.
    if runtime_rel and runtime_tag:
        url = f"https://raw.githubusercontent.com/dotnet/runtime/{runtime_tag}/{runtime_rel}"
        try:
            with urllib.request.urlopen(url, timeout=20) as r:
                if r.status == 200:
                    txt = r.read().decode("utf-8", "replace").split("\n")
                    _SOURCE_CACHE[build_path] = txt
                    _SOURCE_PROVENANCE[build_path] = "tag"
                    return txt
        except Exception:
            pass

    _SOURCE_CACHE[build_path] = None
    return None


# Palette and layout carried over from the reviewed Harness.ZipEncryption report.
# Theme tokens are declared in three places so all three viewer states resolve:
# bare :root (light), prefers-color-scheme guarded against an explicit light
# choice, and the explicit dark stamp.
CSS = """
:root {
  --ground:#f7f8fa; --surface:#ffffff; --surface-2:#f0f2f6;
  --ink:#12161f; --ink-2:#4a5262; --ink-3:#79808f;
  --rule:#dfe3ea; --rule-2:#eceff4;
  --accent:#4557a7;
  --hit:#2f7d64; --hit-bg:#e6f2ed; --hit-stripe:#4ea287;
  --miss:#b5504a; --miss-bg:#fbeae8; --miss-stripe:#d0736c;
  --none:#aeb4c0;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --ground:#0f1319; --surface:#161b23; --surface-2:#1c222c;
    --ink:#e6e9ef; --ink-2:#a2aab8; --ink-3:#6f7787;
    --rule:#262d38; --rule-2:#1f252f;
    --accent:#8b9bdc;
    --hit:#6cc0a2; --hit-bg:#14261f; --hit-stripe:#3e8a70;
    --miss:#e0847d; --miss-bg:#2a1917; --miss-stripe:#a45a54;
    --none:#4c5361;
  }
}
:root[data-theme="dark"] {
  --ground:#0f1319; --surface:#161b23; --surface-2:#1c222c;
  --ink:#e6e9ef; --ink-2:#a2aab8; --ink-3:#6f7787;
  --rule:#262d38; --rule-2:#1f252f;
  --accent:#8b9bdc;
  --hit:#6cc0a2; --hit-bg:#14261f; --hit-stripe:#3e8a70;
  --miss:#e0847d; --miss-bg:#2a1917; --miss-stripe:#a45a54;
  --none:#4c5361;
}
* { box-sizing:border-box; }
body { margin:0; background:var(--ground); color:var(--ink);
  font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  font-size:15px; line-height:1.6; -webkit-font-smoothing:antialiased; }
.mono { font-family:ui-monospace,"SF Mono","Cascadia Code",Menlo,Consolas,monospace; }
.wrap { max-width:1180px; margin:0 auto; padding:56px 28px 96px;
  display:flex; flex-direction:column; gap:44px; }
.eyebrow { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:11px;
  letter-spacing:.16em; text-transform:uppercase; color:var(--accent); margin:0 0 14px; }
h1 { font-size:clamp(28px,4.2vw,42px); line-height:1.12; letter-spacing:-.022em;
  margin:0 0 14px; text-wrap:balance; font-weight:640; }
.lede { margin:0; color:var(--ink-2); max-width:66ch; font-size:16.5px; }
h2 { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:11.5px;
  letter-spacing:.16em; text-transform:uppercase; color:var(--ink-3);
  margin:0 0 18px; font-weight:600; }
.tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:1px;
  background:var(--rule); border:1px solid var(--rule); border-radius:10px; overflow:hidden; }
.tile { background:var(--surface); padding:18px 20px; display:flex; flex-direction:column; gap:5px; }
.tile-v { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:22px; font-weight:600;
  letter-spacing:-.02em; font-variant-numeric:tabular-nums; }
.tile-l { font-size:11px; letter-spacing:.09em; text-transform:uppercase; color:var(--ink-3); }
.panel { background:var(--surface); border:1px solid var(--rule); border-radius:10px; overflow:hidden; }
.tablewrap { overflow-x:auto; }
table { width:100%; border-collapse:collapse; font-size:13.5px; }
th { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:10.5px; letter-spacing:.11em;
  text-transform:uppercase; color:var(--ink-3); font-weight:600; text-align:left;
  padding:12px 14px; border-bottom:1px solid var(--rule); white-space:nowrap; }
td { padding:9px 14px; border-bottom:1px solid var(--rule-2); white-space:nowrap; }
tr:last-child td { border-bottom:none; }
.fname { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12.5px; }
.num { text-align:right; font-family:ui-monospace,Menlo,Consolas,monospace;
  font-variant-numeric:tabular-nums; }
.strong { font-weight:600; }
.barcell { width:150px; }
.bar { display:block; height:6px; background:var(--surface-2); border-radius:3px;
  overflow:hidden; min-width:110px; }
.bar-fill { display:block; height:100%; border-radius:3px; background:var(--hit-stripe); }
.notes { display:flex; flex-direction:column; gap:8px; padding:14px 16px;
  border:1px solid var(--rule); border-radius:10px; background:var(--surface-2);
  font-size:13px; color:var(--ink-2); }
.tabs { display:flex; flex-wrap:wrap; gap:1px; background:var(--rule);
  border:1px solid var(--rule); border-bottom:none; border-radius:10px 10px 0 0; overflow:hidden; }
.tab { flex:1 1 auto; background:var(--surface-2); border:none; cursor:pointer;
  padding:13px 16px; display:flex; flex-direction:column; gap:3px; align-items:flex-start;
  font:inherit; color:var(--ink-2); transition:background .13s ease,color .13s ease; }
.tab:hover { background:var(--surface); color:var(--ink); }
.tab[aria-selected="true"] { background:var(--surface); color:var(--ink);
  box-shadow:inset 0 2px 0 var(--accent); }
.tab:focus-visible { outline:2px solid var(--accent); outline-offset:-2px; }
.tab-name { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:12.5px; }
.tab-pct { font-family:ui-monospace,Menlo,Consolas,monospace; font-size:11px;
  color:var(--ink-3); font-variant-numeric:tabular-nums; }
.tab[aria-selected="true"] .tab-pct { color:var(--accent); }
.legend { display:flex; flex-wrap:wrap; gap:20px; padding:12px 16px;
  border:1px solid var(--rule); border-top:none; background:var(--surface-2);
  font-size:12px; color:var(--ink-2); }
.key { display:inline-flex; align-items:center; gap:7px; }
.chip { width:11px; height:11px; border-radius:2px; display:inline-block; }
.chip.h { background:var(--hit-stripe); }
.chip.m { background:var(--miss-stripe); }
.chip.n { background:var(--none); }
.code { border:1px solid var(--rule); border-top:none; border-radius:0 0 10px 10px;
  background:var(--surface); max-height:660px; overflow:auto;
  font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace; font-size:12.5px; line-height:1.62; }
.row { display:flex; align-items:flex-start; border-left:3px solid transparent; }
.row.h { background:var(--hit-bg); border-left-color:var(--hit-stripe); }
.row.m { background:var(--miss-bg); border-left-color:var(--miss-stripe); }
.ln { flex:0 0 52px; text-align:right; padding:0 12px 0 8px; color:var(--ink-3);
  font-variant-numeric:tabular-nums; user-select:none; }
.hits { flex:0 0 62px; text-align:right; padding-right:14px; font-variant-numeric:tabular-nums;
  font-size:11px; color:var(--ink-3); user-select:none; }
.row.h .hits { color:var(--hit); }
.row.m .hits { color:var(--miss); }
.src { flex:1 1 auto; white-space:pre; padding-right:18px; }
footer { border-top:1px solid var(--rule); padding-top:20px; color:var(--ink-3); font-size:12.5px; }
@media (prefers-reduced-motion: reduce) { * { transition:none !important; } }
"""


def render(ctx):
    def esc(s):
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    notes = []
    if ctx["inputs_used"] < ctx["inputs_total"]:
        notes.append(f"Queue sampled: {ctx['inputs_used']} of {ctx['inputs_total']} inputs replayed. "
                     "Re-run with --all-inputs to replay everything.")
    if ctx["missing_symbols"]:
        notes.append("No symbols available, so these assemblies are absent from this report "
                     "rather than shown as 0%: " + ", ".join(ctx["missing_symbols"]) + ".")
    if ctx["zero_cov"]:
        notes.append(f"{ctx['zero_cov']} file(s) had instrumented lines but none covered; omitted "
                     "from the table. These are usually unrelated code paths in the same assembly.")
    if ctx.get("local_source"):
        notes.append(f"{ctx['local_source']} of the annotated files resolved from a local "
                     "external/ clone, whose version is not guaranteed to match the packaged "
                     "assembly. Line numbers passed bounds and plausibility checks, but subtle "
                     "drift can survive those.")
    for name, why in ctx["skipped"]:
        notes.append(f"No annotated source for {name}: {why}.")

    tiles = "".join(
        f'<div class="tile"><span class="tile-v">{esc(v)}</span>'
        f'<span class="tile-l">{k.replace("_", " ")}</span></div>'
        for k, v in ctx["campaign"].items())
    tiles_html = (f'<section><h2>Campaign</h2><div class="tiles">{tiles}</div></section>'
                  if tiles else "")

    trows = "".join(
        f'<tr><td class="fname">{esc(r["name"])}</td>'
        f'<td class="num">{r["inst"]}</td><td class="num">{r["hit"]}</td>'
        f'<td class="num strong">{r["pct"]}%</td>'
        f'<td class="barcell"><span class="bar">'
        f'<span class="bar-fill" style="width:{r["pct"]}%"></span></span></td></tr>'
        for r in ctx["rows"])

    tabs = "".join(
        f'<button class="tab" data-i="{i}" role="tab" aria-selected="false">'
        f'<span class="tab-name">{esc(p["name"])}</span>'
        f'<span class="tab-pct">{p["pct"]}%</span></button>'
        for i, p in enumerate(ctx["panels"]))

    notes_html = ('<div class="notes">' + "".join(f"<span>{esc(n)}</span>" for n in notes) + "</div>"
                  if notes else "")
    source_html = (f'<section><h2>Annotated source</h2><div class="tabs" role="tablist">{tabs}</div>'
                   f'<div class="legend">'
                   f'<span class="key"><span class="chip h"></span> executed</span>'
                   f'<span class="key"><span class="chip m"></span> instrumented, never executed</span>'
                   f'<span class="key"><span class="chip n"></span> not instrumented</span>'
                   f'</div><div class="code" id="code"></div></section>'
                   if ctx["panels"] else "")

    payload = json.dumps(ctx["panels"]).replace("<", "\\u003c")
    used, total = ctx["inputs_used"], ctx["inputs_total"]

    return f"""<title>{esc(ctx['harness'])} coverage</title>
<style>{CSS}</style>
<div class="wrap">
  <header>
    <p class="eyebrow">AFL++ · SharpFuzz · source-level coverage</p>
    <h1>{esc(ctx['harness'])}</h1>
    <p class="lede">Coverage of <span class="mono">{esc(ctx['library'])}</span>, measured by
    replaying {used} of {total} corpus inputs through the harness under
    <span class="mono">dotnet-coverage</span>. Percentages are over instrumented lines only.</p>
  </header>
  {tiles_html}
  {notes_html}
  <section>
    <h2>Per-file coverage</h2>
    <div class="panel tablewrap">
      <table>
        <thead><tr><th>File</th><th style="text-align:right">Instrumented</th>
        <th style="text-align:right">Covered</th><th style="text-align:right">%</th><th></th></tr></thead>
        <tbody>{trows}</tbody>
      </table>
    </div>
  </section>
  {source_html}
  <footer>Files with instrumented lines but none covered are omitted from the table.
  Annotated source is shown only where the resolved source passed bounds and plausibility
  checks against the coverage line numbers.</footer>
</div>
<script id="panels" type="application/json">{payload}</script>
<script>
const PANELS = JSON.parse(document.getElementById('panels').textContent);
const codeEl = document.getElementById('code');
const tabs = [...document.querySelectorAll('.tab')];
function esc(s) {{ return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }}
function render(i) {{
  const p = PANELS[i];
  codeEl.innerHTML = p.lines.map(l => {{
    const cls = l.h > 0 ? 'h' : (l.h === 0 ? 'm' : '');
    const hits = l.h > 0 ? (l.h > 9999 ? '9999+' : l.h) : (l.h === 0 ? '0' : '');
    return '<div class="row ' + cls + '"><span class="ln">' + l.n + '</span>' +
           '<span class="hits">' + hits + '</span>' +
           '<span class="src">' + (esc(l.t) || ' ') + '</span></div>';
  }}).join('');
  codeEl.scrollTop = 0;
  tabs.forEach(t => t.setAttribute('aria-selected', String(+t.dataset.i === i)));
}}
tabs.forEach(t => t.addEventListener('click', () => render(+t.dataset.i)));
if (tabs.length) render(0);
</script>
"""


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

    # Alignment: a coverage line beyond EOF means the source is a different version.
    src = ["int a = 1;", "int b = 2;", "int c = 3;"]
    ok, why = check_alignment(src, {1: 1, 2: 0, 3: 1})
    check("align: accepts matching source", ok, why)

    ok, why = check_alignment(src, {1: 1, 99: 1})
    check("align: rejects out-of-bounds line", not ok and "beyond" in why, why)

    # Plausibility: instrumented lines are statements. A file whose "instrumented"
    # lines are mostly blanks, comments or braces is misaligned.
    drifted = ["", "// comment", "{", "}", "int real = 1;"]
    ok, why = check_alignment(drifted, {1: 1, 2: 1, 3: 1, 4: 1, 5: 1})
    check("align: rejects implausible lines", not ok and "%" in why, why)

    # 1 non-statement out of 12 is 8.3%, under the 10% threshold.
    fine = ["int x = %d;" % i for i in range(11)] + ["}"]
    ok, why = check_alignment(fine, {i: 1 for i in range(1, 13)})
    check("align: tolerates a few braces", ok, why)

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

    lib_files = {k: v for k, v in cov.items()
                 if a.library.split(".")[0].lower() in k.lower()} or cov

    rows, zero_cov = [], 0
    for path, lines in sorted(lib_files.items()):
        hit, inst = file_stats(lines)
        if inst == 0:
            continue
        if hit == 0:
            zero_cov += 1
            continue
        rows.append({"path": path, "name": path.split("/")[-1],
                     "hit": hit, "inst": inst, "pct": round(100 * hit / inst, 1),
                     "missing": inst - hit})
    rows.sort(key=lambda r: -r["missing"])

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    panels, skipped = [], []
    for r in rows[:a.max_files]:
        src = resolve_source(r["path"], root, a.source_root, a.runtime_tag)
        if src is None:
            skipped.append((r["name"], "source not found"))
            continue
        ok, why = check_alignment(src, lib_files[r["path"]])
        if not ok:
            skipped.append((r["name"], why))
            continue
        hits = lib_files[r["path"]]
        panels.append({"name": r["name"], "pct": r["pct"], "hit": r["hit"], "inst": r["inst"],
                       "lines": [{"n": i + 1, "t": src[i], "h": hits.get(i + 1, -1)}
                                 for i in range(len(src))]})

    n_local = sum(1 for r in rows[:a.max_files]
                  if _SOURCE_PROVENANCE.get(r["path"]) == "local")
    html = render({"harness": a.harness, "library": a.library, "local_source": n_local,
                   "inputs_used": a.inputs_used, "inputs_total": a.inputs_total,
                   "missing_symbols": [s for s in a.missing_symbols.split() if s],
                   "zero_cov": zero_cov, "rows": rows, "panels": panels, "skipped": skipped,
                   "campaign": read_fuzzer_stats(a.fuzzer_stats)})
    os.makedirs(os.path.dirname(os.path.abspath(a.output)), exist_ok=True)
    open(a.output, "w", encoding="utf-8").write(html)
    print(f"wrote {a.output} ({len(rows)} files, {len(panels)} source panels)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
