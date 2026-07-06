# blog-post/

Sources of the public write-up built from this benchmark, plus the adjudication record behind
its numbers.

| File | What it is |
|---|---|
| `post.html` | The write-up itself: a self-contained HTML fragment (scoped CSS, inline JS, no external assets). The generated sections between the `V1MATRIX` and `CASEBROWSER` markers are produced by `gen_post_sections.py`; the prose around them is hand-written. |
| `plausible-not-fixed.html` | The same content wrapped as a complete standalone HTML page, ready to host anywhere. Produced by `make_standalone.py`; a build artifact, deliberately not committed — regenerate it after editing `post.html`. Do not edit it directly. |
| `plausible-not-fixed-hosted.html` | The committed hosted snapshot of the standalone page: same content plus an embed mode (hides the hero when iframed). |
| `gen_post_sections.py` | Regenerates the round-one results matrix and the 33-case browser inside `post.html` from the run data (`../../runs/`, `../../two-axis.json`, `../../human-review.json`, `../../cases32.json`). |
| `make_standalone.py` | Wraps `post.html` into `plausible-not-fixed.html`. Run it after any change to `post.html`. |
| `VERDICT-ADJUDICATION.md` | The full human adjudication: the rubric, all 66 verdicts, the compile checks, the two flaws found in our own benchmark and their corrections, and the record of the external review round. This is the receipts document the write-up points to. |

To update the write-up: edit `post.html` (or the generator and its inputs), then

```bash
python3 gen_post_sections.py    # only if run data or verdicts changed
python3 make_standalone.py
```
