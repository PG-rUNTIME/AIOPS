"""Render docs/media/demo.mp4 and demo.gif from scripts/media/timeline.json.

Needs Playwright (Chromium) and ffmpeg. The page (demo.html) draws one frame per
call to ``render(sim_minutes, end_card_opacity)``; we screenshot every frame.
"""

from __future__ import annotations

import itertools
import shutil
import subprocess
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).parent
OUT = HERE.parents[1] / "docs" / "media"
FRAMES = HERE / "_frames"
FPS, DURATION = 30, 15.5
# (video seconds, simulated minutes): slow down around detection and the ETA update
KEYS = [(0, -3), (1.5, 0), (4.6, 3.3), (7.0, 9.5), (9.2, 11.6), (11.6, 20.3), (12.4, 21)]


def sim_minutes(t: float) -> float:
    for (a, x), (b, y) in itertools.pairwise(KEYS):
        if t <= b:
            return x + (y - x) * (t - a) / (b - a)
    return 21.0


def main() -> None:
    shutil.rmtree(FRAMES, ignore_errors=True)
    FRAMES.mkdir()
    page_file = HERE / "_page.html"
    data = (HERE / "timeline.json").read_text()
    page_file.write_text((HERE / "demo.html").read_text().replace("__DATA__", data))
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 720})
        page.goto(page_file.resolve().as_uri())
        for i in range(int(FPS * DURATION)):
            t = i / FPS
            end = max(0.0, min(1.0, (t - 12.6) / 0.6))
            page.evaluate(f"render({sim_minutes(t):.4f}, {end:.3f})")
            page.screenshot(path=str(FRAMES / f"f{i:04d}.jpg"), type="jpeg", quality=92)
        browser.close()
    mp4, gif = OUT / "demo.mp4", OUT / "demo.gif"
    tmp = OUT / "demo.tmp.mp4"
    subprocess.run(
        [
            "ffmpeg",
            "-loglevel",
            "error",
            "-y",
            "-framerate",
            str(FPS),
            "-i",
            str(FRAMES / "f%04d.jpg"),
            "-c:v",
            "libx264",
            "-crf",
            "20",
            "-preset",
            "veryfast",
            "-pix_fmt",
            "yuv420p",
            "-movflags",
            "+faststart",
            str(tmp),
        ],
        check=True,
    )
    tmp.rename(mp4)
    palette = (
        "fps=12,scale=960:-1:flags=lanczos,split[a][b];"
        "[a]palettegen=max_colors=128:stats_mode=diff[p];"
        "[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle"
    )
    subprocess.run(
        ["ffmpeg", "-loglevel", "error", "-y", "-i", str(mp4), "-vf", palette, str(gif)],
        check=True,
    )
    shutil.rmtree(FRAMES)
    page_file.unlink()
    print(f"wrote {mp4} and {gif}")


if __name__ == "__main__":
    main()
