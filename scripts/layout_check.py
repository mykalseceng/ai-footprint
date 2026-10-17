#!/usr/bin/env python3
"""Render the dashboard or the static report in headless Chrome and measure what tests cannot.

For each page and width it reports a page that scrolls sideways, tables that scroll sideways
at desktop width and words split mid-word. For the dashboard it also reports script errors
and dates left in raw ISO form, checks that every tile and signals-grid cell on screen
shows exactly the figure in the run's document, and checks that no data is lost: every
string value in the document must appear on some page other than "Run data", which shows
the raw document. Optionally it saves a screenshot per page. Exit status is 1 when anything
fails. A scratch copy without the CSP is measured, so the measuring script can run.

Usage:
    scripts/layout_check.py ai-footprint-dashboard.html [--widths 1280,500] [--shots DIR]
    scripts/layout_check.py report.html [--widths 1280,500] [--shots DIR]
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
CATCH = (
    "<script>window.__errors = []; addEventListener('error', "
    "(e) => window.__errors.push(String(e.message)));</script>"
)
MEASURE = r"""
<script>
(async () => {
  // Visit every internal link the dashboard renders (pages, tabs, each finding's panel),
  // open everything collapsible, and measure. Routes under #data show the raw document,
  // so they are measured for layout but never count towards data coverage.
  const wait = () => new Promise((resolve) => setTimeout(resolve, 40));
  const ISO = /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/g;
  const doc = JSON.parse(document.getElementById('audit-data').textContent);
  const out = {pages: {}, errors: window.__errors, missing: [], leaves: 0, figures: []};
  const textOf = () => [...document.body.children]
    .filter((el) => !el.matches('script, style, #layout-result'))
    .map((el) => el.textContent)
    .join(' ');
  const figureOf = (key) => {
    const [scope, id] = key.split(':');
    const list = scope === 'machine' ? doc.views.figures.machine : doc.views.figures.tools[scope];
    return (list || []).find((f) => f.id === id);
  };
  const queue = [''];
  const visited = new Set();
  let seen = '';
  while (queue.length && visited.size < 600) {
    const route = queue.shift();
    if (visited.has(route)) continue;
    visited.add(route);
    location.hash = route;
    await wait();
    document.querySelectorAll('details').forEach((d) => (d.open = true));
    document.querySelectorAll('[aria-expanded="false"]').forEach((b) => b.click());
    document.querySelectorAll('[hidden]').forEach((el) => {
      if (!el.closest('script')) el.hidden = false;
    });
    await wait();
    for (const a of document.querySelectorAll('a[href^="#"]')) {
      const next = a.getAttribute('href').slice(1);
      if (!visited.has(next)) queue.push(next);
    }
    const raw = route.replace(/^#/, '').startsWith('data');
    const result = {wide: [], splits: 0, overflow: 0, iso: 0};
    result.overflow = Math.max(0, document.scrollingElement.scrollWidth - innerWidth);
    for (const t of document.querySelectorAll('table')) {
      const box = t.parentElement;
      if (box.scrollWidth > box.clientWidth + 1) {
        result.wide.push([...t.querySelectorAll('th')].map((th) => th.textContent).join('|')
          + ` ${box.clientWidth}->${box.scrollWidth}`);
      }
    }
    const prose = 'main td, main li, main p, main dd, .drawer li, .drawer p';
    for (const el of document.querySelectorAll(prose)) {
      const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
      let node;
      while ((node = walker.nextNode())) {
        for (const m of node.data.matchAll(/[A-Za-z]{3,}/g)) {
          const r = document.createRange();
          r.setStart(node, m.index); r.setEnd(node, m.index + m[0].length);
          const tops = new Set([...r.getClientRects()].map((x) => Math.round(x.top)));
          if (tops.size > 1) result.splits += 1;
        }
      }
    }
    if (!raw) {
      const text = textOf();
      result.iso = (text.match(ISO) || []).length;
      seen += ' ' + text;
    }
    for (const tile of document.querySelectorAll('[data-figure]')) {
      const f = figureOf(tile.dataset.figure);
      const value = tile.querySelector('[data-figure-value]');
      const text = value ? value.textContent : 'missing';
      if (!f || text !== f.display) {
        const want = f ? f.display : 'none';
        out.figures.push(`#${route} ${tile.dataset.figure}: shows ${text}, data ${want}`);
      }
    }
    for (const cell of document.querySelectorAll('[data-cell]')) {
      const [lens, column] = cell.dataset.cell.split(':');
      const want = String(doc.views.signals_matrix[lens][column]);
      const value = cell.querySelector('[data-cell-value]');
      const text = value ? value.textContent : cell.textContent;
      if (text !== want) {
        out.figures.push(`#${route} grid ${lens}/${column}: shows ${text}, data ${want}`);
      }
    }
    out.pages[route || '(home)'] = result;
  }
  out.routes = visited.size;
  const home = doc.host.home;
  const squash = (text) => text.replace(/\s+/g, ' ').trim();
  // References and keys that tie the document together; the values they point at are shown.
  const STRUCTURAL = new RegExp('(^|\\.)(id|exposure_id|finding_id|topic|tone|identity)$'
    + '|^checklist\\.\\d+\\.exposures\\.|^views\\.host\\.across\\.'
    + '|(secret_scan\\.kinds|tokens)\\.\\d+\\.kind$');
  const shown = (value, keepTicks) => {
    let text = keepTicks ? String(value) : String(value).replaceAll('`', '');
    if (home.length > 1) text = text.split(home + '/').join('~/');
    if (text === home) text = '~';
    const iso = /(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})(?::\d{2})?(?:\.\d+)?(?:\+00:00|Z| UTC)?/g;
    text = text.replace(iso, '$1 $2 UTC');
    return squash(text);
  };
  seen = squash(seen);
  const walk = (value, path) => {
    if (value === null || typeof value !== 'object') {
      if (typeof value !== 'string' || value.trim().length < 2 || STRUCTURAL.test(path)) return;
      out.leaves += 1;
      const forms = [shown(value), shown(value, true), squash(String(value))];
      if (!forms.some((form) => seen.includes(form))) {
        out.missing.push(`${path}: ${String(value).slice(0, 80)}`);
      }
      return;
    }
    for (const [k, v] of Object.entries(value)) walk(v, path ? `${path}.${k}` : k);
  };
  walk(doc, '');
  const pre = document.createElement('pre');
  pre.id = 'layout-result';
  pre.textContent = JSON.stringify(out);
  document.body.append(pre);
})();
</script>
"""

# The static report shows one page at a time with CSS :target; measuring shows them all.
REPORT_MEASURE = """
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


def scratch_copy(page: Path, directory: Path) -> Path:
    """A copy of the page without its CSP, with error capture and the measuring script."""
    html = page.read_text(encoding="utf-8")
    html = re.sub(r'<meta http-equiv="Content-Security-Policy"[^>]*>', "", html, flags=re.S)
    if 'id="audit-data"' in html:
        html = html.replace("<body>", "<body>" + CATCH, 1).replace("</body>", MEASURE + "</body>")
    else:
        html = html.replace("<body>", "<body>" + CATCH, 1) + REPORT_MEASURE
    copy = directory / "dashboard.html"
    copy.write_text(html, encoding="utf-8")
    return copy


def headless(browser: str, profile: Path, *args: str) -> str:
    """Run headless Chrome with a throwaway profile and return its stdout."""
    return subprocess.run(  # noqa: S603 - fixed argv, browser path from CHROME or PATH
        [
            browser,
            "--headless",
            "--disable-gpu",
            "--no-first-run",
            "--hide-scrollbars",
            f"--user-data-dir={profile}",
            "--virtual-time-budget=600000",
            *args,
        ],
        capture_output=True,
        text=True,
        check=False,
    ).stdout


def measure(browser: str, copy: Path, width: int, profile: Path) -> dict:
    """Per-page measurements and the data-coverage result from one render at ``width``."""
    dom = headless(browser, profile, f"--window-size={width},900", "--dump-dom", copy.as_uri())
    match = re.search(r'<pre id="layout-result">(.*?)</pre>', dom, re.S)
    if not match:
        sys.exit(f"Chrome returned no measurement at width {width}")
    text = match.group(1).replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"')
    return json.loads(text.replace("&amp;", "&"))


def page_status(result: dict, width: int) -> list[str]:
    """Problems on one page; sideways tables only count at desktop widths."""
    problems = []
    if result.get("overflow"):
        problems.append(f"page scrolls sideways by {result['overflow']}px")
    if result["wide"] and width >= 1000:
        problems.append(f"{len(result['wide'])} wide tables")
    if result["splits"]:
        problems.append(f"{result['splits']} split words")
    if result.get("iso"):
        problems.append(f"{result['iso']} raw ISO dates")
    return problems


def report(results: dict, width: int) -> bool:
    """Print one line per page and the coverage result; True when everything passed."""
    ok = not results.get("errors")
    for error in results.get("errors", []):
        print(f"{width:>5}px  script error: {error}")
    for page, result in results.get("pages", results).items():
        problems = page_status(result, width)
        ok = ok and not problems
        print(f"{width:>5}px  {page:<18} {'; '.join(problems) or 'ok'}")
        if width >= 1000:
            for wide in result["wide"]:
                print(f"          sideways scroll: {wide}")
    return ok


def main() -> int:
    """Measure every page at every width; print one line per page."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("page", type=Path, help="dashboard or static report HTML")
    parser.add_argument("--widths", default="1280,500")
    parser.add_argument("--shots", type=Path, help="directory for one screenshot per page/width")
    args = parser.parse_args()
    browser = chrome()
    passed = True
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        copy = scratch_copy(args.page, directory)
        for index, width in enumerate(int(w) for w in args.widths.split(",")):
            results = measure(browser, copy, width, directory / "profile")
            passed = report(results, width) and passed
            if index == 0 and "missing" in results:
                missing = results["missing"]
                print(
                    f"data coverage: {results['leaves'] - len(missing)}/{results['leaves']} "
                    "values shown outside Run data"
                )
                for line in missing:
                    print(f"          missing: {line}")
                shown = results["figures"]
                print(f"figures on screen: {'match the data' if not shown else 'MISMATCH'}")
                for line in shown:
                    print(f"          {line}")
                passed = passed and not missing and not shown
            if args.shots:
                args.shots.mkdir(parents=True, exist_ok=True)
                for page in results.get("pages", results):
                    if "?" in page:
                        continue
                    shot = args.shots / f"{page.replace('/', '_')}-{width}.png"
                    url = f"{args.page.resolve().as_uri()}#{page}"
                    headless(
                        browser,
                        directory / "profile",
                        f"--window-size={width},3000",
                        f"--screenshot={shot}",
                        url,
                    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
