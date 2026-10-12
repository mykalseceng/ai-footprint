#!/usr/bin/env python3
"""Render the HTML report in headless Chrome and measure what CSS checks cannot.

For each page and width it reports tables that scroll sideways and words split mid-word,
and optionally saves a screenshot per page. Exit status is 1 when anything overflows or
splits. The report's CSP forbids scripts, so a scratch copy without the CSP is measured.

Usage:
    scripts/layout_check.py ai-footprint-report.html [--widths 1280,500] [--shots DIR]
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CHROME = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "google-chrome",
    "chromium",
    "chromium-browser",
)
MEASURE = """
<script>
document.querySelectorAll('.view').forEach(v => v.style.display = 'block');
document.querySelectorAll('details').forEach(d => d.open = true);
const out = {};
for (const section of document.querySelectorAll('section.view')) {
  const page = {wide: [], splits: 0};
  for (const t of section.querySelectorAll('.tbl')) {
    if (t.scrollWidth > t.clientWidth + 1) {
      page.wide.push([...t.querySelectorAll('th')].map(h => h.textContent).join('|')
        + ` ${t.clientWidth}->${t.scrollWidth}`);
    }
  }
  for (const td of section.querySelectorAll('td, li, p')) {
    const walker = document.createTreeWalker(td, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) {
      for (const m of node.data.matchAll(/[A-Za-z]{3,}/g)) {
        const r = document.createRange();
        r.setStart(node, m.index); r.setEnd(node, m.index + m[0].length);
        const tops = new Set([...r.getClientRects()].map(x => Math.round(x.top)));
        if (tops.size > 1) page.splits += 1;
      }
    }
  }
  out[section.id] = page;
}
const pre = document.createElement('pre');
pre.id = 'layout-result';
pre.textContent = JSON.stringify(out);
document.body.append(pre);
</script>
"""


def chrome() -> str:
    """Path to a Chrome or Chromium binary, or exit with a message."""
    for candidate in CHROME:
        found = candidate if Path(candidate).is_file() else shutil.which(candidate)
        if found:
            return found
    sys.exit("Chrome or Chromium is required for layout checks")


def scratch_copy(report: Path, directory: Path) -> Path:
    """A copy of the report without its CSP, with the measuring script appended."""
    html = report.read_text(encoding="utf-8")
    html = re.sub(r'<meta http-equiv="Content-Security-Policy"[^>]*>', "", html, flags=re.S)
    copy = directory / "report.html"
    copy.write_text(html + MEASURE, encoding="utf-8")
    return copy


def measure(browser: str, copy: Path, width: int, profile: Path) -> dict:
    """Per-page overflow and split-word counts from one headless render at ``width``."""
    dom = subprocess.run(  # noqa: S603 - fixed argv, browser path from CHROME or PATH
        [
            browser,
            "--headless",
            "--disable-gpu",
            "--no-first-run",
            f"--user-data-dir={profile}",
            f"--window-size={width},900",
            "--virtual-time-budget=3000",
            "--dump-dom",
            copy.as_uri(),
        ],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    match = re.search(r'<pre id="layout-result">(.*?)</pre>', dom, re.S)
    if not match:
        sys.exit(f"Chrome returned no measurement at width {width}")
    return json.loads(match.group(1).replace("&gt;", ">").replace("&quot;", '"'))


def screenshot(browser: str, report: Path, page: str, width: int, out: Path, profile: Path) -> None:
    """Save one screenshot of ``page`` rendered at ``width``."""
    subprocess.run(  # noqa: S603 - fixed argv, browser path from CHROME or PATH
        [
            browser,
            "--headless",
            "--disable-gpu",
            "--no-first-run",
            "--hide-scrollbars",
            f"--user-data-dir={profile}",
            f"--window-size={width},4000",
            f"--screenshot={out}",
            f"{report.resolve().as_uri()}#{page}",
        ],
        capture_output=True,
        check=False,
    )


def main() -> int:
    """Measure every page at every width; print one line per page."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("report", type=Path)
    parser.add_argument("--widths", default="1280,500")
    parser.add_argument("--shots", type=Path, help="directory for one screenshot per page/width")
    args = parser.parse_args()
    browser = chrome()
    failed = False
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        copy = scratch_copy(args.report, directory)
        for width in (int(w) for w in args.widths.split(",")):
            results = measure(browser, copy, width, directory / "profile")
            for page, result in sorted(results.items()):
                status = "ok"
                if result["wide"] or result["splits"]:
                    failed = True
                    status = f"{len(result['wide'])} wide, {result['splits']} split words"
                print(f"{width:>5}px  {page:<14} {status}")
                for wide in result["wide"]:
                    print(f"          sideways scroll: {wide}")
                if args.shots:
                    args.shots.mkdir(parents=True, exist_ok=True)
                    screenshot(
                        browser,
                        args.report,
                        page,
                        width,
                        args.shots / f"{page}-{width}.png",
                        directory / "profile",
                    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
