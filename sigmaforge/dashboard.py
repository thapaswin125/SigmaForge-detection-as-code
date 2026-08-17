"""Self-contained HTML dashboard generator.

Renders docs/dashboard.html from real data: the detection outcomes
computed by sigmaforge.report (every rule against every fixture), the
ATT&CK coverage, and each rule's converted Lucene query. No external
assets, no network, opens straight in a browser.

CLI: python -m sigmaforge.dashboard
"""

from __future__ import annotations

import html
import sys
from collections import defaultdict
from datetime import date

from sigma.data.mitre_attack import mitre_attack_tactics, mitre_attack_techniques

from sigmaforge.convert import convert_rule_to_lucene
from sigmaforge.loader import REPO_ROOT, discover_rule_paths, load_rule
from sigmaforge.report import build_records, summary

# Written as index.html so GitHub Pages serves it at the site root.
DASHBOARD_HTML = REPO_ROOT / "docs" / "index.html"
REPO_URL = "https://github.com/thapaswin125/SigmaForge-detection-as-code"

LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _e(text: object) -> str:
    return html.escape(str(text))


def _queries() -> dict[str, str]:
    out = {}
    for rule_path in discover_rule_paths():
        out[rule_path.stem] = convert_rule_to_lucene(load_rule(rule_path))
    return out


def render() -> str:
    records = build_records()
    s = summary(records)
    queries = _queries()

    by_rule = defaultdict(list)
    for r in records:
        by_rule[r.rule].append(r)

    all_tactics = sorted(set(mitre_attack_tactics.values()))
    covered = set(s["tactics"])

    # Rules sorted by severity then name.
    rule_rows = sorted(
        by_rule.items(),
        key=lambda kv: (LEVEL_ORDER.get(kv[1][0].level, 9), kv[0]),
    )

    tp_pct = round(100 * s["tp_caught"] / max(s["true_positives"], 1))
    fp_pct = round(100 * s["fp_suppressed"] / max(s["false_positives"], 1))

    cards = "".join(
        f"""<div class="card">
        <div class="card-num {cls}">{val}</div>
        <div class="card-label">{_e(label)}</div>
      </div>"""
        for val, label, cls in [
            (s["rules"], "detection rules", ""),
            (s["fixtures"], "event fixtures tested", ""),
            (f"{s['correct']}/{s['fixtures']}", "correct outcomes", "good"),
            (f"{tp_pct}%", "attacks caught", "good"),
            (f"{fp_pct}%", "false positives suppressed", "good"),
            (f"{len(covered)}/{len(all_tactics)}", "ATT&CK tactics covered", ""),
        ]
    )

    tactic_chips = "".join(
        f'<span class="chip {"on" if t in covered else "off"}">{_e(t)}</span>'
        for t in all_tactics
    )

    rule_blocks = []
    for rule_name, recs in rule_rows:
        r0 = recs[0]
        techs = ", ".join(
            f"{t} {mitre_attack_techniques.get(t, '')}".strip() for t in r0.techniques
        )
        fixtures = "".join(
            f"""<tr class="{'ok' if rec.correct else 'bad'}">
              <td><span class="dot {rec.kind}"></span>{_e(rec.fixture)}</td>
              <td>{'should fire' if rec.expected_to_fire else 'should stay silent'}</td>
              <td>{'FIRED' if rec.fired else 'silent'}</td>
              <td>{'&#10003;' if rec.correct else '&#10007;'}</td>
              <td class="cmt">{_e(rec.comment)}</td>
            </tr>"""
            for rec in sorted(recs, key=lambda x: x.fixture)
        )
        rule_blocks.append(
            f"""<details class="rule">
        <summary>
          <span class="lvl lvl-{_e(r0.level)}">{_e(r0.level)}</span>
          <span class="rtitle">{_e(r0.title)}</span>
          <span class="rtech">{_e(techs)}</span>
        </summary>
        <table class="fixtures">
          <thead><tr><th>fixture</th><th>intent</th><th>result</th><th></th><th>what it represents</th></tr></thead>
          <tbody>{fixtures}</tbody>
        </table>
        <div class="query-label">Converted Elasticsearch (Lucene) query</div>
        <pre class="query">{_e(queries[rule_name])}</pre>
      </details>"""
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SigmaForge Dashboard</title>
<style>
  :root {{
    --bg: #0f1419; --panel: #171d26; --panel2: #1e2530; --line: #2a3340;
    --fg: #e6edf3; --muted: #8b98a5; --good: #3fb950; --bad: #f85149;
    --accent: #58a6ff; --mal: #d29922;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: var(--bg); color: var(--fg);
    font: 15px/1.5 -apple-system, "Segoe UI", Roboto, sans-serif; }}
  .wrap {{ max-width: 1100px; margin: 0 auto; padding: 32px 20px 64px; }}
  header h1 {{ margin: 0 0 4px; font-size: 26px; }}
  header p {{ margin: 0; color: var(--muted); }}
  .gen {{ font-size: 12px; color: var(--muted); margin-top: 6px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px,1fr));
    gap: 12px; margin: 24px 0; }}
  .card {{ background: var(--panel); border: 1px solid var(--line);
    border-radius: 10px; padding: 16px; }}
  .card-num {{ font-size: 28px; font-weight: 700; }}
  .card-num.good {{ color: var(--good); }}
  .card-label {{ color: var(--muted); font-size: 13px; margin-top: 2px; }}
  h2 {{ font-size: 15px; text-transform: uppercase; letter-spacing: .06em;
    color: var(--muted); margin: 32px 0 12px; }}
  .chips {{ display: flex; flex-wrap: wrap; gap: 8px; }}
  .chip {{ padding: 4px 10px; border-radius: 20px; font-size: 13px; border: 1px solid var(--line); }}
  .chip.on {{ background: rgba(63,185,80,.15); color: var(--good); border-color: rgba(63,185,80,.4); }}
  .chip.off {{ color: var(--muted); opacity: .6; }}
  .rule {{ background: var(--panel); border: 1px solid var(--line);
    border-radius: 10px; margin-bottom: 10px; overflow: hidden; }}
  .rule summary {{ cursor: pointer; padding: 14px 16px; display: flex;
    align-items: center; gap: 12px; flex-wrap: wrap; }}
  .rule summary::-webkit-details-marker {{ display: none; }}
  .rtitle {{ font-weight: 600; }}
  .rtech {{ color: var(--muted); font-size: 13px; }}
  .lvl {{ font-size: 11px; font-weight: 700; text-transform: uppercase;
    padding: 3px 8px; border-radius: 6px; letter-spacing: .04em; }}
  .lvl-high {{ background: rgba(248,81,73,.15); color: var(--bad); }}
  .lvl-medium {{ background: rgba(210,153,34,.15); color: var(--mal); }}
  .lvl-low {{ background: rgba(88,166,255,.15); color: var(--accent); }}
  .lvl-critical {{ background: var(--bad); color: #fff; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  .fixtures {{ margin: 0 16px 12px; }}
  .fixtures th {{ text-align: left; color: var(--muted); font-weight: 500;
    padding: 6px 10px; border-bottom: 1px solid var(--line); }}
  .fixtures td {{ padding: 6px 10px; border-bottom: 1px solid var(--panel2); }}
  tr.bad td {{ background: rgba(248,81,73,.08); }}
  .cmt {{ color: var(--muted); }}
  .dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%;
    margin-right: 8px; vertical-align: middle; }}
  .dot.true_positive {{ background: var(--bad); }}
  .dot.false_positive {{ background: var(--good); }}
  .query-label {{ color: var(--muted); font-size: 12px; margin: 4px 16px; text-transform: uppercase; letter-spacing: .05em; }}
  .query {{ margin: 0 16px 16px; background: #0b0f14; border: 1px solid var(--line);
    border-radius: 8px; padding: 12px; overflow-x: auto; font-size: 12px;
    color: #9ecbff; white-space: pre-wrap; word-break: break-word; }}
  .legend {{ color: var(--muted); font-size: 13px; margin-top: 8px; }}
  .legend .dot {{ margin-left: 12px; }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .topbar {{ display: flex; justify-content: space-between; align-items: flex-start;
    gap: 16px; flex-wrap: wrap; }}
  .ghlink {{ flex: none; display: inline-flex; align-items: center; gap: 7px;
    padding: 8px 14px; border: 1px solid var(--line); border-radius: 8px;
    background: var(--panel); color: var(--fg); font-size: 13px; font-weight: 600; }}
  .ghlink:hover {{ border-color: var(--accent); text-decoration: none; }}
  .ghlink svg {{ width: 16px; height: 16px; fill: currentColor; }}
  footer {{ margin-top: 48px; padding-top: 20px; border-top: 1px solid var(--line);
    color: var(--muted); font-size: 13px; display: flex; justify-content: space-between;
    flex-wrap: wrap; gap: 12px; }}
</style>
</head>
<body>
<div class="wrap">
  <header class="topbar">
    <div>
      <h1>SigmaForge</h1>
      <p>Detection-as-code: every rule tested against real attack and benign events, then converted to a live SIEM query.</p>
      <div class="gen">Generated {date.today().isoformat()} from live test outcomes. Tier 1 and Tier 2 (Elasticsearch) proven identical by the integration suite.</div>
    </div>
    <a class="ghlink" href="{REPO_URL}">
      <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
      View on GitHub
    </a>
  </header>

  <div class="cards">{cards}</div>

  <h2>ATT&CK tactic coverage</h2>
  <div class="chips">{tactic_chips}</div>
  <div class="legend">Green tactics have at least one rule. Grey tactics are honest gaps.</div>

  <h2>Rules and their detection outcomes</h2>
  <div class="legend">
    <span class="dot true_positive"></span>true positive (attack, should fire)
    <span class="dot false_positive"></span>false positive (benign, should stay silent).
    Click a rule to expand.
  </div>
  {"".join(rule_blocks)}

  <footer>
    <span>SigmaForge &middot; Sigma detections with two-tier testing and CI-gated deployment</span>
    <span><a href="{REPO_URL}">Source and full test suite on GitHub</a></span>
  </footer>
</div>
</body>
</html>
"""


def main(argv: list[str] | None = None) -> int:
    DASHBOARD_HTML.parent.mkdir(parents=True, exist_ok=True)
    DASHBOARD_HTML.write_text(render(), encoding="utf-8", newline="\n")
    print(f"wrote {DASHBOARD_HTML.relative_to(REPO_ROOT)}")
    print(f"open it: {DASHBOARD_HTML}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
