# APK Research Platform - web console (`frontend/dist`)

Plain static files, served by the FastAPI app itself. No build step, no npm, no
framework, no CDN, no runtime request to any origin other than the API you point
it at.

```
frontend/dist/index.html   shell: banner, toolbar, view host, task drawer, event log, settings drawer
frontend/dist/styles.css   dark theme, CSS-grid layout, 4/2/1 board columns, drawer overlay under 900px
frontend/dist/app.js       all behaviour (classic script, ES2020, zero innerHTML)
frontend/README.md         this file
```

`app.js` is a single IIFE. Every node is created with `document.createElement`
and filled with `textContent`; there is no `innerHTML`, no `eval`, no template
injected as markup anywhere, including the markdown renderer. The only `http://`
string in the tree is the placeholder text of the settings field.

## Running it

The API mounts `frontend/dist` when the directory exists at app-creation time:

```
GET /        -> frontend/dist/index.html
GET /static/* -> frontend/dist/*   (StaticFiles mount)
```

Local-operator mode (no token):

```powershell
$root = 'D:\ADeespseekSH\REA\apk-research-platform'
$env:PYTHONPATH = "$root\backend"
$env:APKPLAT_STORAGE = "$root\tests\.ui-scratch\storage"
$env:APKPLAT_REQUIRE_AUTH = '0'
& "$root\.venv\Scripts\python.exe" scripts\apkplat_cli.py serve --port 8791
```

Then open `http://127.0.0.1:8791/`.

## Views

| View | Route | Endpoints | Notes |
| --- | --- | --- | --- |
| Board | `#/board` | `GET /api/projects/{id}/board` | four base columns plus the Exceptions group; metrics strip on top |
| Task drawer | (opens over any view) | `GET /api/tasks/{id}`, `GET /api/projects/{id}/evidence?task_id=` | full task JSON, counters, task evidence |
| Projects | `#/projects` | `GET /api/projects`, `POST /api/projects`, `GET /api/queue?project_id=` | list + multipart create + job polling |
| Project overview | `#/project/{id}/overview` | `GET /api/projects/{id}`, `/artifacts`, `/verify`, `GET /api/artifacts/{aid}/text` | manifest facts, signing, artifacts, verify |
| Evidence | `#/project/{id}/evidence` | `GET /api/projects/{id}/evidence`, `GET /api/artifacts/{aid}/text?limit&tail` | click a row to see the excerpt in context |
| Search | `#/project/{id}/search` | `GET /api/projects/{id}/search?q&kind&limit`, `GET /api/projects/{id}/packages` | `file:start_line-end_line` locators |
| Report | `#/project/{id}/report` | `POST /api/projects/{id}/report` | markdown rendered locally |

### Board and the Exceptions group

`GET /api/projects/{id}/board` returns `columns` keyed `TODO/RUNNING/REVIEW/DONE`,
but those buckets are a server-side projection: `WAITING_*`, `BLOCKED`,
`RETRYING` fold into `RUNNING`, and `FAILED`/`CANCELLED`/`STALE` fold into
`REVIEW`. Rendering the payload as-is would either hide the real status or show
the same card twice. The console therefore partitions every card by its own
`status` field:

* base column = cards whose `status` is exactly that column name;
* `Exceptions` = cards with `WAITING_MODEL`, `WAITING_DEVICE`,
  `WAITING_APPROVAL`, `BLOCKED`, `FAILED`, `CANCELLED`, `RETRYING`, `STALE`,
  grouped by status with a count badge.

When every card is an exception the four base columns legitimately read `empty`,
and a one-line hint under the board says why. Pending approvals are listed
read-only: the API accepts decisions through `PATCH /api/tasks/{id}` with
`approval_id`, not through a UI-only route.

Clicking a card opens the drawer: task facts (status, role, priority, attempt,
version, model/tool call counters, evidence count, timestamps), its evidence
table, and the complete task JSON. `POST /api/tasks/{id}/runs` only records a
run - the API exposes no read endpoint for `agent_runs` - so the drawer says so
explicitly and shows the counters instead of inventing rows.

The drawer is `role="dialog"`, moves focus to its close button on open, closes on
`Escape`, and returns focus to the card that opened it.

### Projects list and create

The create form posts real multipart data (`name`, `apk`, `goal`, `policy_id`).
Ingest rejections are shown verbatim: `422` bodies such as
`{"error_code":"zip_slip","message":"1 entry names escape the archive root: [...]"}`
appear as `Ingest rejected - zip_slip` plus the untouched message; other failures
use the generic error path (`HTTP <status> - <error_code> - <message>`). After a
successful create the returned `job_id` is displayed and `GET /api/queue?project_id=`
is polled every 1.5 s until the job leaves `PENDING`/`RUNNING` (`RETRYING` is
kept in the live set), then the project list is refreshed.

The UI only reads the queue; something must consume it. With no worker the line
correctly stays at `queue: PENDING - attempt 0/3` forever. Start a worker
(`scripts\apkplat_cli.py worker --once --kinds static_pipeline`, which drains the
queue once) and the same line becomes `queue: SUCCEEDED - attempt 1/3`, followed
by a muted `Pipeline finished. Reload the project view to see artifacts.` hint.
Note that `worker --once` can exit after the jobs it saw when it started, so a
job created while it was running may need a second launch (see the browser run
below, which used two).

### Evidence excerpts

Each evidence row (table of `id/kind/claim/artifact/confidence`) is focusable
(`tabindex=0`, Enter/Space) and loads the artifact text with
`GET /api/artifacts/{id}/text?limit=20000&tail=false`. The excerpt is located
inside that text; if it is not in the truncated head, the request is retried with
`tail=true`. Around the hit the console shows 25 lines of context with the
matching lines highlighted, plus kind/byte/truncation metadata.

### Search and packages

`q`, `kind` (`class`/`method`/`field`) and `limit` build
`GET /api/projects/{id}/search`; results render `kind`, class, member, the
`file:start_line-end_line` locator and the indexed preview. Selecting a row shows
the full locator/signature and the preview text. `GET /api/projects/{id}/packages`
renders the package table and every `stats` value.

### Metrics

The strip renders every key returned by `GET /api/metrics` with its name and
value. `null` is rendered as `no data` (the API uses `null` for rates with no
denominator); no threshold, colour band or verdict is invented.

### Live events

`EventSource` on `GET /api/events/stream?after=<lastSeq>&project_id=<id>` (plus
`&token=` in token mode - `EventSource` cannot send headers). Frames are appended
to the `aria-live="polite"` log with seq, time, type, actor and a one-line
payload, capped at 400 rows. Reconnects are manual with exponential backoff
(1.5 s doubling to 15 s). On error the console probes `GET /api/health`: a 401
stops retrying and raises the auth banner instead of looping.

## Auth modes

`POST /api/projects` etc. are guarded by `settings.require_auth`
(`APKPLAT_REQUIRE_AUTH`).

* **local** (`APKPLAT_REQUIRE_AUTH=0`): no header needed, `/api/health` reports
  `auth_mode: "local"`, the log panel footer says `local operator mode`.
* **token** (default): every request needs `Authorization: Bearer <token>`, and
  the event stream needs `?token=<token>`.

The settings drawer (toolbar, "Settings") holds **base URL** and **token** and
persists them in `localStorage` under `apkplat.baseUrl`, `apkplat.token` (and
`apkplat.projectId` for the selected project). The base URL may stay empty, which
means "same origin as the page". "Test" performs `GET /api/health` against the
entered values and prints the status code and `auth_mode`; "Forget token" removes
it and reconnects the stream.

Any `401` - including from the event stream - shows a banner at the top of the
page with the error code, the failing path, and `Open settings` / `Retry`
buttons. The view under it renders an explicit message ("This server needs a
bearer token...") instead of an empty page.

## Markdown renderer

`renderMarkdown()` supports level 1-3 headings, paragraphs, unordered/ordered
lists, blockquotes, fenced code blocks, pipe tables with alignment, and inline
`code`, **bold** and *em*. It never parses HTML: input is split into text tokens
and each token is placed with `textContent`, so `<script>` in a report body is
inert text. Link syntax is deliberately left as text, because following it would
mean an external request.

## Accessibility and layout

* real `<button>` elements for every action; tabs use `aria-current="page"`;
  clickable table rows are focusable and activate on Enter/Space;
* the event log is `aria-live="polite"`; the drawer is a labelled dialog with
  focus management; `#main` carries `tabindex="-1"`;
* `Escape` closes the settings drawer first, then the task drawer;
* no page-level horizontal scrolling: the shell is a fixed grid with
  `overflow:hidden` and only the view column scrolls. Wide tables scroll inside
  their own `.tablewrap`;
* board columns: 4 at >=1200px, 2 at 901-1199px, 1 (stacked) at <=900px, where
  the task drawer also becomes an overlay.

## How this was verified

Scratch storage only - the live `storage/` directory was never touched.

```powershell
$root = 'D:\ADeespseekSH\REA\apk-research-platform'
$py   = "$root\.venv\Scripts\python.exe"
$env:PYTHONPATH = "$root\backend"
$env:APKPLAT_STORAGE = "$root\tests\.ui-scratch\storage"
$env:APKPLAT_REQUIRE_AUTH = '0'
$env:LOGURU_LEVEL = 'WARNING'

& $py scripts\apkplat_cli.py init
& $py scripts\apkplat_cli.py create --name ui-check --apk samples\sample-app.apk
& $py scripts\apkplat_cli.py worker --once --kinds static_pipeline
& $py scripts\apkplat_cli.py serve --port 8791
```

`scripts\ui_smoke.py` is the endpoint contract check the UI was written against
(kept in the repo, stdlib only):

```powershell
& $py scripts\ui_smoke.py --base http://127.0.0.1:8791
```

Observed result (`18/18 passed`, exit 0), against project
`prj_17b76e569fbf4f4cbc38d8215aa0d3a1` / `ui-check`:

```
PASS  GET /api/health                                auth_mode=local queue={'SUCCEEDED': 1}
PASS  GET /api/projects                              1 project(s); newest=prj_17b76... (ui-check)
PASS  GET /api/projects/{id}                         pkg=com.example.reef v1.2.3 cert=4b09702f4886...
PASS  GET /api/projects/{id}/board                   3 card(s), 0 pending approval(s)
PASS  GET /api/projects/{id}/artifacts               17 artifact(s): findings, index, metadata, report, ...
PASS  GET /api/artifacts/{id}/text?limit&tail=false  kind=metadata bytes=2560 text=2560ch tail=False
PASS  GET /api/artifacts/{id}/text?limit&tail=true   kind=metadata bytes=2560 text=2560ch tail=True
PASS  GET /api/projects/{id}/evidence                12 row(s): manifest_fact, network_endpoint, permission, secret_candidate
PASS  GET /api/projects/{id}/verify                  artifacts 17/17 ok, traceability=1.0 overall_ok=True
PASS  POST /api/projects/{id}/report                 artifact=art_aeda1a14... rows=12 markdown=6203ch
PASS  GET /api/projects/{id}/search?q=               2 hit(s); first=com/example/reef/MainActivity.java:13
PASS  GET /api/projects/{id}/packages                1 package(s); classes=8 index=90112B
PASS  GET /api/metrics                               11 numeric, 3 null (rendered as 'no data')
PASS  GET /api/queue?project_id=                     stats={'SUCCEEDED': 1} live=0 of 1
PASS  GET /api/events/stream (SSE)                   8 frame(s) parsed as JSON with id/seq/event_type
PASS  GET /  +  /static/*                            / -> 200, 4393B; /static/app.js -> 200, 75700B, text/javascript; /static/styles.css -> 200, 15365B, text/css
PASS  404 error envelope                             404 detail.error_code='project_not_found'
PASS  POST /api/projects (hostile APK -> 422)        422 error_code='zip_slip' message="1 entry names escape the archive root: ['../../escape.txt']"
```

The script inspects the newest project unless `--project <id>` is passed
(`--token` sets a bearer token, `--mutate`/`--skip-ingest` control the write
paths; `python scripts\ui_smoke.py --help`). A second run after restarting the
server, against a fresh `ui-order-check` project with an empty board, also passed
`18/18` (`board 0 card(s)`, `verify artifacts 9/9 ok, traceability=1.0
overall_ok=True`). Card and artifact counts depend on what has been run in the
scratch storage; the checks themselves are the same.

Browser check. A real headless browser was available (Microsoft Edge 156/157 on
this machine) and the console was driven over the DevTools protocol - launching
Edge with `--screenshot` alone never terminates because the page holds an open
SSE connection, so `tests\.ui-scratch\cdp_ui_check.py` navigates, waits, probes
the DOM and calls `Page.captureScreenshot`. Observed:

| Probe | Result |
| --- | --- |
| `GET /` shell, 1280x900 | `horizontalOverflow=false` (`scrollWidth == clientWidth == 1280`) |
| board columns | 4 `col` nodes, `grid-template-columns` = `302px 302px 302px 302px` |
| board at 820px | `grid-template-columns` = `769px` (single stacked column), `horizontalOverflow=false` |
| exceptions | card status `BLOCKED` appears once, under `Exceptions -> BLOCKED (3)`, and `baseColumnCards = 0` (no duplicate in `RUNNING`) |
| metrics strip | 14 metrics rendered, names and values, 3 rendered as `no data` |
| task drawer | opens (`app drawer-open`), `focused=drawer-close`, sections `Runs`/`Evidence`/`Full task JSON`, runs-gap note present, JSON `<pre>` present |
| verify button | `ok-box`, text `PASS artifact chain 20/20 ok traceability 1` (the chain count grows by one every time the report button is pressed in the same storage) |
| evidence row click | excerpt panel with 27 code lines, 1 highlighted line, text `"package": "com.example.reef",` |
| search `onCreate` | 2 rows: `com/example/reef/MainActivity.java:13-22`, `com/example/reef/ReefProvider.java:13-15`; packages table 1 row + all `stats` values |
| report button | markdown rendered: H1 + 10 H2 sections, 1 table, 1 fenced block, 9 lists, 59 inline code nodes, 0 `<script>` inside the rendered region |
| live events | `conn="connected"`, 32 event rows after earlier smoke runs |
| create form, hostile APK | `Ingest rejected - zip_slip` plus the verbatim `1 entry names escape the archive root: ['../../escape.txt']` |
| create form, real APK | ok-box `Ingested ui-create-check - prj_e5ff835877244e3db4bb6754cee79319` / `job_id job_2a1d20cc1a844039af9662376275fa6b`, queue line `queue: PENDING - attempt 0/3`, then `queue: SUCCEEDED - attempt 1/3` once a worker drained the queue, project table refreshed with `INGESTED` |

Token mode (`APKPLAT_REQUIRE_AUTH=1`, `APKPLAT_SECRET=ui-token-secret`, second
server on port 8792, token minted with `POST /api/auth/token` and
`X-Admin-Secret`):

| Scenario | Result |
| --- | --- |
| page loaded without a token | banner visible: `Not authorized - HTTP 401 - missing_token - Authorization header required`, buttons `Open settings` / `Retry`; metrics area shows `HTTP 401 - missing_token`; board explains that a bearer token is needed; `conn="error"`; no blank page |
| token in `localStorage` + reload | banner hidden, 4 columns, 14 metrics, `conn="connected"`, 32 log rows, `apkplat.token` persisted |

Screenshots from those runs are in `tests\.ui-scratch\shots\`
(`board-1280.png`, `board-820.png`, `board-drawer.png`, `projects-1280.png`,
`overview-1280.png`, `evidence-1280.png`, `search-1280.png`, `report-1280.png`,
`auth-401.png`, `auth-token.png`, `create-flow.png`). The scratch server, its log
and the render helpers (`cdp_ui_check.py`, `cdp_debug.py`, `token_mode_check.py`,
`create_flow_check.py`) live under `tests\.ui-scratch\` and are verification
tools, not part of the deliverable. Counts in the tables above are a snapshot of
that run; every `report` press adds an artifact, so `artifacts`/`verify` totals
grow as the button is used.

## Ambiguous shapes and what was assumed

1. **Board columns vs. card status.** Assumed the four columns are a projection
   and re-partitioned by `card.status` (see above). Verified against a `BLOCKED`
   task that the server places in `RUNNING`.
2. **Project row keys.** `GET /api/projects` returns raw table rows, so the
   package and hash are `package_name` and `apk_sha256`; the UI never reads
   `package`/`sha256`. (`scripts\apkplat_cli.py` `list` does read those keys and
   raises `KeyError: 'package'` - a pre-existing CLI bug, left alone.)
3. **Metrics.** Assumed `null` means "not measurable yet", rendered as `no data`
   rather than `0`.
4. **Search results contain no artifact id.** The UI shows the indexed
   `preview`/`signature` for a hit and labels it as coming from the code index;
   there is no endpoint that maps `file:line` back to a file on disk, and none
   was invented.
5. **Task runs.** No `GET` endpoint for `agent_runs` exists; the drawer states
   that instead of showing fabricated rows.
6. **Approvals.** Listed read-only; decisions go through
   `PATCH /api/tasks/{id}` with `approval_id`, which the console does not expose
   as a button because the UI was not asked to mutate tasks.
7. **Artifact view.** There is no download route, so artifacts are shown as text
   (`limit=20000`, with the `truncated` flag surfaced). Binary artifacts such as
   `index.db` render as whatever `text()` returns; the byte size is always shown
   next to it.
8. **SSE frames.** `data:` is the JSON of the audit-event row; `id` is the
   sequence. The client also accepts a missing `seq` and falls back to the
   `lastEventId`.

## Known gaps in the API (reported, not patched)

* no read endpoint for `agent_runs`, so run history is invisible to any UI;
* the static pipeline creates no task rows, so a freshly ingested project has an
  empty board - the console says so instead of inventing tasks;
* `scripts\apkplat_cli.py list` raises `KeyError: 'package'`;
* no per-artifact download endpoint (text only, capped at 2,000,000 chars);
* `POST /api/projects/{id}/report` is a write operation and generates a new
  report artifact each time it is pressed - the console does not call it on page
  load.
* Observed, not root-caused: a long-running API process reported
  `evidence.failures = [{"reason": "excerpt_hash_mismatch"}]` for every evidence
  row of projects ingested after that process started (`traceability_rate=0.0`,
  `ok=false`), while the same database verified clean (`1.0`) in a freshly
  started server and in-process. The row `excerpt`/`excerpt_hash` values matched
  the database exactly in both cases, so this looks like process-lifetime state
  in the API rather than bad evidence. The UI simply renders the answer it gets:
  a failing verify shows a red box with the failure rows instead of hiding them.
  Re-running the smoke script after restarting the server is the workaround used
  for the numbers above.
