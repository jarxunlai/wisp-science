# Browser Runtime architecture

Wisp extension 0.4.3 treats the Chrome extension as a **controlled access adapter**.
The desktop process owns sessions, waits, staging, and approval.

```
Agent tools
    -> Browser Runtime (src-tauri/src/browser_bridge)
        -> ws://127.0.0.1:18765  shared / daily Chrome
        -> ws://127.0.0.1:<allocated-port>/<instance-token>  project workspace
            -> Manifest V3 extension (browser-extension/)
```

## Sessions

| Session | Browser | Login state | Port |
|---|---|---|---|
| `shared` | User's existing Chrome/Edge profile | Daily cookies and extensions | 18765 |
| `workspace` | Per-project Chrome-family profile under the app data directory, `browser-workspaces/<SHA-256(project_id)>/profile` | Persistent for that project | OS-allocated loopback port |

Both can be connected at once. Omitting `session` always selects `shared`;
workspace mode is used only when a tool explicitly passes `session=workspace`.

Each resolved lane has an independent Browser Task Lease, held until the turn
completes. `shared` remains one globally serialized lane. The tool-facing
`workspace` alias resolves from the trusted ToolEnv project id into that
project's running instance; tools reject missing project context and never
accept another project's internal lane name. Multiple projects can therefore
use their own workspaces concurrently while shared Chrome remains protected.

The registry owns each process, listener, profile path, extension copy, and
connection identity. Profile and extension directories use a SHA-256 digest
of the opaque project id, never a raw path component. Every start assigns a
new lane generation and WebSocket URL token. A client must present both the
bundled extension origin and the correct token, so a stale extension cannot
attach to a different project after a port is reused. Tabs, selected tabs,
pending requests, turn ledgers and human-verification state use resolved lanes.

Lifecycle transitions are serialized; normal commands on independent lanes
remain concurrent. Up to three workspace instances may run at once. At the
limit, start fails with instructions to stop an idle project's workspace.
Repeated starts reuse the existing process. `stop_workspace` stops only the
current project's instance, fails its pending requests, and drops its tab and
human-verification records. Project deletion also stops that project's instance.
Profiles are retained for the same project's later login sessions; the old
unscoped `browser-workspace` profile is never adopted by an arbitrary project.
After app restart, old workspace cleanup and human-verification records are
discarded because tab ids are process-local; shared records retain their
existing recovery behavior. Closing a Wisp window still leaves its running
sessions alive; idle-window reclamation and a dedicated workspace status UI
remain follow-up work.

## Tab ownership and the project window

A lane lease stops two projects from driving one browser at the same time,
but it does not decide *which tabs* an agent may touch. Since extension
0.4.3 the Runtime also scopes every browser tool to the calling
conversation (#1617, phase 1):

- **Scope.** Each tool call derives a `ToolScope` (resolved lane, project
  id, conversation frame id) from the trusted ToolEnv only — never from tool
  arguments. Browser tools exist only on the main agent, so the frame is the
  agent's identity. Without a project and a frame (the CLI, older tests)
  there is no scope and no enforcement, matching the lease skip rule.
- **Ownership.** Each lane keeps a memory-only map from tab id to the
  owning project and frame. A tab is owned when `web_open_tab` or a JSON
  `tabs.create` opens it, when a tab the conversation operates opens it as a
  popup (the extension's `newTabs` carry `openerTabId`; only tabs whose
  opener is the operated tab are adopted), or when the user approves a grant.
- **Enforcement.** One check (`authorize_tab` / `select_tab`) gates every
  path: `web_scan` (including `tabs_only`), `web_execute_js`,
  `web_screenshot`, `web_save_assets` and `web_agent_*`. Without
  `switch_tab_id` a tool picks the conversation's last selected tab, else its
  first owned tab — never the profile's active or first tab — and fails with
  instructions when the conversation has none. Selection is remembered per
  frame, not per lane. Tab lists returned by `{"cmd":"tabs"}` and a close
  command's `remaining` are filtered to the scope.
- **Embedded references.** `web_execute_js` parses JSON commands the way
  the extension does: `tabs.close` `tabIds`/`tabId`, `tabs.switch` `tabId`
  and `cdp` `tabId` must be owned (integral floats such as `42.0` count as
  ids), and CDP `Target.*` and `Browser.*` methods are refused because they
  reach other targets and windows. A script shaped like a JSON object that
  serde cannot parse is refused rather than run as page JavaScript.
- **Grants.** An explicit tab id (or `switch_tab_id: "active"`, the user's
  focused tab outside Wisp's project windows) that exists but is not owned
  triggers an approval prompt naming the tab's title and URL, and whether
  another conversation or project controls it. Approving moves ownership to
  the caller; refusing fails the call before anything reaches the extension.
  An "auto-approve everything" approval scope auto-approves this prompt too.
- **Fixed project window.** With the `window_binding` capability, a scoped
  `tabs.create` carries the project's bound `windowId`; the first one sends
  `newWindow: true` and the returned window id is bound to the project on
  that lane. Opens that bind a window are serialized. If the bound window
  was closed, the extension returns `window_gone`; the Runtime clears the
  binding, opens a new window for the same project, rebinds it, and says so
  in the tool result (`window_note`). It never falls back to the focused
  window. An extension without `window_binding` keeps opening tabs in the
  current window and the result says the fixed window is unavailable;
  ownership is still enforced bridge-side.
- **Lifetime.** Ownership and window bindings are memory only. The
  extension reports a per-browser-run id (`browser_instance`, kept in
  `chrome.storage.session`); on a connection's first handshake the lane's
  owners and bindings are cleared unless the run id matches, because a
  restarted Chrome reuses tab and window ids. A service-worker restart keeps
  them. An app restart, an extension without a run id, or stopping a project
  workspace drops them, so ownership only ever shrinks. Closing tabs through
  Wisp removes their owners.
- **Needs-human commands.** Confirming or focusing a verification tab from
  the app acts only on tabs whose recorded frame belongs to the window's
  project; the frame id the UI sends back is not trusted.

**This is tab isolation, not account isolation.** Every tab in the shared
profile shares its cookies, sign-ins and site storage. Use a project
workspace when logins must be separated.

Turn-end cleanup still uses the per-turn ledger of tabs Wisp created; the
shared-lane lease and project workspaces are unchanged. Native tab groups,
an in-app ownership display, grant management, persistence across restarts
and download attribution are phase 2 follow-ups.

### Workspace mode needs a build that still loads unpacked extensions

The workspace window is launched with `--load-extension` pointed at a copy
of `browser-extension/` whose `session_config.js` targets its own allocated endpoint and instance token.
**Official Google Chrome removed that flag in version 137** and now only
logs `--load-extension is not allowed in Google Chrome, ignoring`, so the
window opens with no Wisp extension. Chromium and Chrome for Testing keep
the flag.

So `resolve_browser()` prefers a build that honors the flag (Chromium,
Chrome for Testing, or whatever `WISP_WORKSPACE_BROWSER` points at) and
falls back to branded Chrome only because releases older than 137 still
work. `start_workspace` then **waits up to 20 s for the workspace
extension to connect**; if it never does it closes the window and fails
with `WORKSPACE_EXTENSION_BLOCKED` explaining the flag removal and the
shared-session alternative. It never reports a spawned process as ready,
which used to leave the agent driving a blank `about:blank` window (#952).

Shared mode is unaffected: the user loads the extension once from
`chrome://extensions` in the browser they already use. Wisp validates the
release package (manifest version, stable extension id, required files, and
SHA-256 inventory) and stages it under the application's stable data directory.
Chrome remembers that managed path instead of a version-dependent release
resource path.

When the running shared extension is older than the staged package, the app
shows both versions and the exact managed path. Extension 0.3.1 and later expose
`runtime_reload`, so future compatible upgrades can acknowledge a reload
request, restart their service worker, reconnect, and be rechecked without a
Chrome click. Older extensions cannot receive that control operation. Wisp then
opens the extension manager, copies the managed path, and waits for the user to
click **Reload** (or load the unpacked managed directory once). The app polls
the handshake and clears the update banner only after the required version is
actually connected.

### When a connected extension is not a usable session

The extension popup only reports whether its own socket is open, so it can
read *Connected to Wisp* while Wisp reports `connected=false`.
`browser_setup` therefore names the cause instead of only the symptom:

| Field | Meaning |
|---|---|
| `refused_connection` | A client reached a bridge port and was refused — a foreign extension id, or another loopback bridge on the port. Carries the observed `origin`, the `expected_origin`, and the handshake error. |
| `update_required` / `reload_required` | A connected extension is below the bundled version, below `protocol_version` 2, or reported no capabilities. `browser_setup action=update_extension` refreshes and verifies the managed copy, then either reloads a capable extension or returns `manual_reload_required`. |

## What the extension does

- Handshake: `extension_version`, `protocol_version=2`, `capabilities[]`, `browser_instance`
- Tab creation in a bound project window, or a new dedicated window (`window_binding`); `window_gone` when the bound window is closed
- `newTabs` in each result with `openerTabId`, so popups can be attributed
- Controlled service-worker reload (`runtime_reload`) after the managed package is verified
- Conditional wait (URL / selector / text / settle)
- Article scan (`images[]`, `figures[]`, `code_blocks[]`)
- Host-permission asset download into `Downloads/WispBrowserStaging`
- Viewport / full-page / selector capture
- Pause control from the popup (`USER_CONTROLLING`)
- Side panel (`side_panel`): on the user's request it reads the active tab's
  text and selection, sends the question as `side_ask`, and renders the
  `side_*` events of the resulting turn. It is the only traffic the extension
  initiates; pausing agent control does not disable it.

The extension never writes project directories and never returns large base64 files as the archive path.

## What the Runtime does

- Multiplexes one shared listener and up to three project workspace listeners
- Per-session Browser Task Leases with `shared` as the default and explicit
  `workspace` routing
- Copies staged files into the project and hashes SHA-256
- Starts/stops the workspace browser window and verifies it connected
- Per-conversation tab ownership, grant prompts, and one bound browser window per project (see above)
- Per-turn ledger of tabs Wisp created (`web_open_tab` / tab-create), closed at turn end or confirmed in the UI
- Records the last refused connection so an unclaimed extension has a reason
- Maintains and verifies the stable shared-extension directory and rechecks the
  handshake after every update attempt
- In-browser chat one-shot (`web_agent_send` / `wait` / `read`) on an
  already-logged-in ChatGPT, Gemini, or Google AI Mode tab
- Runs a side panel question as an IM-origin agent turn in the main window's
  project (`browser_bridge/side_panel.rs`). A new panel conversation creates a
  session titled after the page; `side_started`, `side_delta`, `side_tool`,
  `side_approval`, and `side_done` / `side_error` return on the connection that
  asked.

Playwright is not used. The user's daily Chrome User Data directory is never passed as `--user-data-dir`.

## Safety checks

- `side_*` messages are honoured only from the live, origin-checked extension
  connection of their session. The panel can stop a turn or answer an approval
  only in conversations it has sent a message to since Wisp started, and an
  approval needs its exact id. Page text and the selection are length-capped,
  quoted as untrusted content, and cannot close their own quoting block. The
  panel receives tool names, never tool arguments or results. It renders the
  reply's Markdown into a fixed set of tags built node by node (`markdown.js`),
  never through `innerHTML`; links are limited to `http(s)` and `mailto`.

- `web_agent_*` accepts only already-open HTTPS tabs at `chatgpt.com` /
  `chat.openai.com`, `gemini.google.com`, or `google.com` with `udm=50`
  (Google AI Mode). Lookalike hosts such as `chatgpt.com.evil.com` or
  `gemini.google.com.evil.com` are rejected before any prompt is filled.
  Ordinary `google.com/search` tabs without `udm=50` are not treated as chat.
- `web_save_assets` `dest_dir` and `web_screenshot` `save_path` must be
  project-relative: absolute paths and `..` segments are rejected, so tool
  arguments cannot write outside the project root.
- The extension's pause gate parses each incoming command and lets only
  `cmd:"control"` through while paused; it never sniffs the raw request
  string.
