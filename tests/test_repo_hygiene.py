"""What must never be tracked."""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_no_tracked_symlinks_and_no_node_modules():
    """2026-11-15: a worktree's ui/node_modules symlink was committed (`ui/node_modules/` ignores directories only);
    the fast-forward replaced the main tree's real node_modules with a symlink to itself."""
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-s"], capture_output=True, text=True, check=True).stdout
    links = [ln.split("\t", 1)[1] for ln in out.splitlines() if ln.startswith("120000 ")]
    assert links == [], links
    assert not [p for p in out.splitlines() if "node_modules" in p.split("\t", 1)[-1]]


def test_every_tracked_screenshot_is_used_somewhere():
    """R6.5: 45 of 66 screenshots were referenced by nothing (README, decks, gallery, sample builder). A screenshot
    is kept only while some tracked file names it; regenerate with scripts/live-shots.sh when a page needs one."""
    import subprocess
    root = Path(__file__).resolve().parents[1]
    shots = subprocess.run(["git", "-C", str(root), "ls-files", "docs/screenshots"], capture_output=True, text=True,
                           check=True).stdout.split()
    names = [Path(s).name for s in shots]
    pats = [x for n in names for x in ("-e", n)]          # one -e per name: `-e a b` reads b as a path
    others = subprocess.run(["git", "-C", str(root), "grep", "-l", "-F", *pats, "--", ":!docs/screenshots"],
                            capture_output=True, text=True, check=False).stdout.split() if names else []
    text = "".join((root / f).read_text("utf-8", "ignore") for f in others)
    assert [n for n in names if n not in text] == []


def test_no_build_info_is_tracked():
    import subprocess
    root = Path(__file__).resolve().parents[1]
    tracked = subprocess.run(["git", "-C", str(root), "ls-files"], capture_output=True, text=True, check=True).stdout
    assert not [f for f in tracked.split() if f.endswith(".tsbuildinfo")]
