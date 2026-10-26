//! Loopback bridge to a user-installed Chrome/Chromium extension.
//!
//! The extension runs inside the user's existing browser profile, so page
//! execution keeps that profile's cookies, login state, extensions, GPU, and
//! browser fingerprint. Wisp never launches a separate automation browser.
//!
//! Design acknowledgement: this bridge is inspired by GenericAgent's GA Web /
//! TMWebDriver real-browser architecture and compatible loopback protocol:
//! https://github.com/lsdefine/GenericAgent (MIT, Copyright 2025 lsdefine).
//! This module is Wisp's independent Rust implementation; see
//! `browser-extension/NOTICE.md` for provenance details.

use crate::workspace_surface::WorkspaceManager;
use async_trait::async_trait;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_hdr_async, WebSocketStream};
use uuid::Uuid;
use wisp_dto::{
    BrowserExtensionSetup, BrowserExtensionStatus, BrowserExtensionUpdateResult,
    BrowserNeedsHumanConfirmResult, BrowserNeedsHumanPrompt, BrowserNeedsHumanTab,
    BrowserTabCleanupItem, BrowserTabCleanupPrompt,
};
use wisp_llm::ToolSchema;
use wisp_store::Store;
use wisp_tools::{Approval, ImageData, Tool, ToolEnv, ToolResult};

use crate::browser_url_filters::{self, BrowserUrlFilters};

mod chat_site;
mod errors;
mod extension_manager;
mod project_workspace;
pub(crate) mod side_panel;
mod workspace;

const BRIDGE_ADDR: &str = "127.0.0.1:18765";
const REQUIRED_PROTOCOL: i64 = 2;
const EXTENSION_ID: &str = "gnkjgagleagkgdlkkcianolobfdoocnp";
const EXTENSION_ORIGIN: &str = "chrome-extension://gnkjgagleagkgdlkkcianolobfdoocnp";
const BROWSER_DISCONNECTED_CODE: &str = "browser_extension_disconnected";
const BROWSER_DISCONNECTED_MARKER: &str = "WISP_BROWSER_DISCONNECTED";
const DISCONNECTED_ASSISTANT_INSTRUCTION: &str = "Live web retrieval is unavailable. Do not answer live, latest, current, or URL-specific questions from prior knowledge. Tell the user this turn contains no live web retrieval, relay the install steps, and wait until status is connected. Only continue from memory if they explicitly ask for a knowledge-only answer.";
const STALE_ASSISTANT_INSTRUCTION: &str = "A connected extension is older than this Wisp build, so parts of the browser toolset will fail. Call browser_setup with action=update_extension first. It verifies and prepares the managed extension directory and automatically reloads compatible extension versions. If the result says manual_reload_required, relay current and bundled versions plus extension_path exactly, then ask the user to Reload Wisp Real Browser Bridge on chrome://extensions and call browser_setup again to recheck. Do not claim the newer tools exist until update_required is false.";
const DEFAULT_TIMEOUT_MS: u64 = 15_000;
const MAX_TIMEOUT_MS: u64 = 60_000;
const AUTO_LAUNCH_WAIT: Duration = Duration::from_secs(15);
/// How long `start_workspace` waits for the launched browser's extension to
/// reach the workspace port before declaring the window unusable.
const WORKSPACE_CONNECT_WAIT: Duration = Duration::from_secs(20);
const MAX_SCRIPT_BYTES: usize = 64 * 1024;
const MAX_RESULT_CHARS: usize = 200_000;
/// Base64 payload ceiling for one screenshot, matching the shared image path's
/// 5 MB decoded limit (base64 inflates by 4/3).
const MAX_SCREENSHOT_B64: usize = 7 * 1024 * 1024;
const PENDING_CLEANUP_KEY: &str = "browser_tab_cleanup_pending";
const PENDING_NEEDS_HUMAN_KEY: &str = "browser_needs_human_pending";
/// Error code the extension returns when a project's bound window is gone.
const WINDOW_GONE_CODE: &str = "window_gone";
const WINDOW_BINDING_UNAVAILABLE: &str = "Fixed project window unavailable: the connected extension does not support window_binding, so this tab opened in the browser's current window. Call browser_setup with action=update_extension to get a dedicated window per project. Tab ownership checks still apply.";
const WINDOW_REBOUND_NOTE: &str = "This project's browser window was closed, so Wisp opened a new window for the project and now uses it for new tabs. Tabs that were in the closed window are gone.";
const TAB_ISOLATION_NOTE: &str = "Only this conversation's tabs are listed: tabs it opened, popups they opened, and tabs the user shared. Open more with web_open_tab, or pass switch_tab_id=\"active\" (or a tab id) to ask the user for access to another tab. This isolation separates tabs, not cookies or accounts: every tab shares the profile's sign-ins.";

/// Where `tabs.create` should put a new tab.
#[derive(Clone, Copy, Debug)]
enum TabPlacement {
    /// The browser's current window (no binding: unscoped or old extension).
    Current,
    /// The project's bound window.
    Window(i64),
    /// A new dedicated window, which the bridge then binds to the project.
    NewWindow,
}

#[derive(Clone, Debug, Serialize)]
pub struct BrowserTab {
    id: i64,
    url: String,
    title: String,
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    window_id: Option<i64>,
}

#[derive(Clone, Debug)]
struct TrackedTab {
    session: String,
    tab_id: i64,
    initial_url: String,
    url: String,
    title: String,
    #[allow(dead_code)]
    created_at: i64,
}

impl TrackedTab {
    fn to_item(&self) -> BrowserTabCleanupItem {
        BrowserTabCleanupItem {
            session: self.session.clone(),
            tab_id: self.tab_id,
            url: self.url.clone(),
            title: self.title.clone(),
            initial_url: self.initial_url.clone(),
        }
    }
}

#[derive(Clone, Debug)]
struct TurnTabLedger {
    turn_id: String,
    frame_id: String,
    tabs: Vec<TrackedTab>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingCleanup {
    prompt: BrowserTabCleanupPrompt,
    #[serde(default)]
    auto_close: bool,
}

/// What `complete_turn` decided to do with tabs Wisp opened this turn.
#[derive(Debug)]
pub enum TabCleanupAction {
    None,
    Closed,
    Prompt(BrowserTabCleanupPrompt),
}

#[derive(Clone)]
struct BridgeClient {
    connection_id: u64,
    session: String,
    tx: mpsc::UnboundedSender<Message>,
}

#[derive(Clone, Debug, Default)]
struct SessionMeta {
    protocol_version: i64,
    extension_version: String,
    capabilities: Vec<String>,
    paused: bool,
    /// Per-browser-run id from the extension (empty for older extensions).
    /// Chrome restarts tab ids from scratch when the browser restarts.
    browser_instance: String,
}

/// The conversation allowed to drive a tab. Browser tools exist only on the
/// main agent, so the conversation frame is the agent's identity.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TabOwner {
    project_id: String,
    frame_id: String,
}

/// Who is calling a browser tool, derived only from the trusted `ToolEnv`
/// (never from tool arguments). `None` — no project or frame, as in the CLI
/// and older tests — means no tab isolation, like the occupancy skip rule.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ToolScope {
    lane: String,
    project_id: String,
    frame_id: String,
}

impl ToolScope {
    fn owner(&self) -> TabOwner {
        TabOwner {
            project_id: self.project_id.clone(),
            frame_id: self.frame_id.clone(),
        }
    }

    fn owns(&self, slot: &SessionState, tab_id: i64) -> bool {
        slot.owners.get(&tab_id).is_some_and(|owner| {
            owner.project_id == self.project_id && owner.frame_id == self.frame_id
        })
    }
}

/// Owners are remembered past the tab list's HTTP(S) filter (a tab briefly on
/// a non-HTTP page keeps its owner). Chrome never reuses a tab id within one
/// browser run, so only an oversized map is pruned to the live tabs.
const MAX_TRACKED_OWNERS: usize = 512;

#[derive(Default)]
struct SessionState {
    client: Option<BridgeClient>,
    tabs: BTreeMap<i64, BrowserTab>,
    /// Selected tab per conversation frame; unscoped callers use "".
    selected_by_frame: HashMap<String, i64>,
    /// Which conversation may drive each tab in this lane. Memory only: an
    /// app restart forgets it, and a new browser run clears it.
    owners: HashMap<i64, TabOwner>,
    /// The dedicated window each project's new tabs open in.
    project_windows: HashMap<String, i64>,
    /// Whether the current connection has delivered its first handshake.
    handshaken: bool,
    pending: HashMap<String, oneshot::Sender<Result<BridgeReply, String>>>,
    meta: SessionMeta,
}

/// A client that reached a bridge port but was never claimed as the Wisp
/// extension. Kept so `browser_setup` can say *why* the extension popup shows
/// "Connected to Wisp" while Wisp reports `connected=false`.
#[derive(Clone, Debug)]
struct RefusedConnection {
    session: String,
    origin: Option<String>,
    reason: String,
}

#[derive(Default)]
struct BridgeState {
    sessions: HashMap<String, SessionState>,
    startup_error: Option<String>,
    workspaces: HashMap<String, project_workspace::ProjectWorkspace>,
    last_refusal: Option<RefusedConnection>,
    extension_update_error: Option<String>,
}

pub struct BrowserBridge {
    state: Mutex<BridgeState>,
    next_connection_id: AtomicU64,
    bundled_extension_dir: PathBuf,
    extension_dir: PathBuf,
    managed_extension: bool,
    store: Option<Store>,
    /// Production `start()` only. Tests must not spawn a real browser.
    can_launch: bool,
    launch_lock: Mutex<()>,
    workspace_lifecycle: Mutex<()>,
    extension_update_lock: Mutex<()>,
    /// Tabs `web_open_tab` / tab-create commands opened, keyed by turn id.
    turn_ledgers: Mutex<HashMap<String, TurnTabLedger>>,
    pending_cleanups: Mutex<HashMap<String, PendingCleanup>>,
    /// Tabs whose current page needs a human to complete a CAPTCHA / robot
    /// check. Keyed by `(session, tab_id)` so a later turn's auto-close cannot
    /// take them, and so the UI can remind the user independently of the LLM.
    needs_human: Mutex<HashMap<(String, i64), BrowserNeedsHumanTab>>,
    needs_human_tx: Mutex<Option<mpsc::UnboundedSender<Vec<BrowserNeedsHumanTab>>>>,
    /// Where the extension's side panel requests go. They start agent turns,
    /// which the bridge cannot do itself.
    side_panel_tx: Mutex<Option<mpsc::UnboundedSender<side_panel::SideRequest>>>,
    /// One lease per real browser session. Occupancy is held from the first
    /// browser tool of a project+turn until `complete_turn`, not per tool call
    /// — two tools in the same turn must not open a gap a foreign project can
    /// sneak into. Independent sessions can still serve different projects in
    /// parallel.
    occupancy: StdMutex<HashMap<String, BrowserOccupancy>>,
    /// Serializes opens that create and bind a project window, so two calls
    /// cannot each open a window for the same project.
    window_bind_lock: Mutex<()>,
}

struct BrowserOccupancy {
    project_id: String,
    turns: HashSet<String>,
}

#[derive(Clone, Debug)]
struct BridgeReply {
    value: Value,
    ready: Option<bool>,
    wait: Option<Value>,
    /// Tabs created while the command ran, with the tab that opened them.
    new_tabs: Vec<NewTab>,
}

#[derive(Clone, Debug)]
struct NewTab {
    id: i64,
    opener: Option<i64>,
}

struct BrowserExecution {
    session: String,
    tab_id: i64,
    value: Value,
    ready: Option<bool>,
    wait: Option<Value>,
    /// Popups the operated tab opened, now owned by the caller's scope.
    adopted_tabs: Vec<i64>,
}

fn session_slot<'a>(state: &'a mut BridgeState, name: &str) -> &'a mut SessionState {
    state.sessions.entry(name.to_string()).or_default()
}

fn session_summary(state: &BridgeState, name: &str, bundled_version: Option<&str>) -> Value {
    let slot = state.sessions.get(name);
    let connected = slot.and_then(|session| session.client.as_ref()).is_some();
    let meta = slot.map(|session| &session.meta);
    let protocol_version = meta.map(|meta| meta.protocol_version).unwrap_or(0);
    let capabilities = meta
        .map(|meta| meta.capabilities.clone())
        .unwrap_or_default();
    let update_required =
        connected && meta.is_some_and(|meta| session_requires_update(meta, bundled_version));
    let automatic_reload_available = connected
        && capabilities
            .iter()
            .any(|capability| capability == "runtime_reload");
    json!({
        "connected": connected,
        "extension_version": meta.map(|meta| meta.extension_version.clone()).unwrap_or_default(),
        "protocol_version": protocol_version,
        "capabilities": capabilities,
        "paused": meta.map(|meta| meta.paused).unwrap_or(false),
        "tabs": slot.map(|session| session.tabs.len()).unwrap_or(0),
        "reload_required": update_required,
        "update_required": update_required,
        "automatic_reload_available": automatic_reload_available
    })
}

/// Explain a refused connection in the terms the user sees: the popup says
/// connected, Wisp says it is not.
fn refusal_summary(refusal: Option<&RefusedConnection>) -> Value {
    let Some(refusal) = refusal else {
        return Value::Null;
    };
    let session = &refusal.session;
    let explanation = match refusal.origin.as_deref() {
        Some(origin) if !origin.is_empty() => format!(
            "An extension at {origin} reached the {session} port and Wisp refused it, because this bridge only accepts {EXTENSION_ORIGIN}. Its own popup can still read Connected to Wisp while Wisp reports connected=false. Load the bundled extension from extension_path (a repacked or third-party copy gets a different id), and remove any other loopback bridge extension."
        ),
        _ => format!(
            "A client reached the {session} port without completing the Wisp extension handshake, so no session was claimed and Wisp reports connected=false. Another browser bridge or a plain HTTP client is probably using this port; stop it, then reload the Wisp extension."
        ),
    };
    json!({
        "session": session,
        "origin": refusal.origin,
        "expected_origin": EXTENSION_ORIGIN,
        "reason": refusal.reason,
        "explanation": explanation
    })
}

fn bundled_manifest_version(dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(dir.join("manifest.json")).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    value.get("version")?.as_str().map(str::to_string)
}

fn extension_version_outdated(current: &str, bundled: Option<&str>) -> bool {
    let Some(bundled) = bundled else {
        return false;
    };
    match (
        semver::Version::parse(current),
        semver::Version::parse(bundled),
    ) {
        (Ok(current), Ok(bundled)) => current < bundled,
        _ => current != bundled,
    }
}

fn session_requires_update(meta: &SessionMeta, bundled_version: Option<&str>) -> bool {
    meta.protocol_version < REQUIRED_PROTOCOL
        || meta.capabilities.is_empty()
        || extension_version_outdated(&meta.extension_version, bundled_version)
}

fn workspace_path_matches(expected: Option<&str>, actual: &str) -> bool {
    expected.is_none_or(|path| path == actual)
}

fn resolve_session_name(requested: Option<&str>) -> Result<String, String> {
    if let Some(name) = requested {
        if name != "shared" && name != "workspace" && !name.starts_with("workspace:") {
            return Err(errors::structured(
                errors::SESSION_REQUIRED,
                "session must be shared or workspace",
                false,
            ));
        }
        return Ok(name.to_string());
    }
    Ok("shared".into())
}

#[allow(dead_code)]
impl BrowserBridge {
    fn construct(extension_dir: PathBuf, store: Option<Store>, can_launch: bool) -> Self {
        Self {
            state: Mutex::new(BridgeState::default()),
            next_connection_id: AtomicU64::new(1),
            bundled_extension_dir: extension_dir.clone(),
            extension_dir,
            managed_extension: false,
            store,
            can_launch,
            launch_lock: Mutex::new(()),
            workspace_lifecycle: Mutex::new(()),
            extension_update_lock: Mutex::new(()),
            turn_ledgers: Mutex::new(HashMap::new()),
            pending_cleanups: Mutex::new(HashMap::new()),
            needs_human: Mutex::new(HashMap::new()),
            needs_human_tx: Mutex::new(None),
            side_panel_tx: Mutex::new(None),
            occupancy: StdMutex::new(HashMap::new()),
            window_bind_lock: Mutex::new(()),
        }
    }

    fn occupy_turn(&self, session: &str, project_id: &str, turn_id: &str) -> Result<(), String> {
        let mut occupancy = self.occupancy.lock().unwrap_or_else(|p| p.into_inner());
        match occupancy.get_mut(session) {
            Some(current) if current.project_id == project_id => {
                current.turns.insert(turn_id.to_string());
                Ok(())
            }
            Some(current) => Err(format!(
                "browser session '{session}' is currently in use by another project ({}). Only one project's agent can drive the same browser session at a time; wait until that turn finishes or stop it.",
                current.project_id,
            )),
            None => {
                occupancy.insert(
                    session.to_string(),
                    BrowserOccupancy {
                        project_id: project_id.to_string(),
                        turns: HashSet::from([turn_id.to_string()]),
                    },
                );
                Ok(())
            }
        }
    }

    fn release_turn(&self, turn_id: &str) {
        let mut occupancy = self.occupancy.lock().unwrap_or_else(|p| p.into_inner());
        occupancy.retain(|_, current| {
            current.turns.remove(turn_id);
            !current.turns.is_empty()
        });
    }

    fn new(extension_dir: PathBuf) -> Self {
        Self::construct(extension_dir, None, false)
    }

    fn new_with_store(extension_dir: PathBuf, store: Store) -> Self {
        Self::construct(extension_dir, Some(store), false)
    }

    pub async fn start(
        bundled_extension_dir: PathBuf,
        managed_extension_dir: PathBuf,
        store: Store,
    ) -> Arc<Self> {
        let update_error =
            extension_manager::sync(&bundled_extension_dir, &managed_extension_dir, EXTENSION_ID)
                .err();
        let mut state = BridgeState::default();
        state.extension_update_error = update_error;
        let bridge = Arc::new(Self {
            state: Mutex::new(state),
            next_connection_id: AtomicU64::new(1),
            bundled_extension_dir,
            extension_dir: managed_extension_dir,
            managed_extension: true,
            store: Some(store),
            can_launch: true,
            launch_lock: Mutex::new(()),
            workspace_lifecycle: Mutex::new(()),
            extension_update_lock: Mutex::new(()),
            turn_ledgers: Mutex::new(HashMap::new()),
            pending_cleanups: Mutex::new(HashMap::new()),
            needs_human: Mutex::new(HashMap::new()),
            needs_human_tx: Mutex::new(None),
            side_panel_tx: Mutex::new(None),
            occupancy: StdMutex::new(HashMap::new()),
            window_bind_lock: Mutex::new(()),
        });
        bridge.load_pending_cleanups().await;
        bridge.load_pending_needs_human().await;
        match TcpListener::bind(BRIDGE_ADDR).await {
            Ok(listener) => {
                let task_bridge = bridge.clone();
                tokio::spawn(async move { task_bridge.accept_loop(listener).await });
            }
            Err(error) => {
                bridge.state.lock().await.startup_error = Some(format!(
                    "cannot listen on {BRIDGE_ADDR}: {error}; stop any other TMWebDriver/Wisp browser bridge using this port"
                ));
            }
        }

        bridge
    }

    async fn setup_info(&self) -> Value {
        let auto_launch = match &self.store {
            Some(store) => browser_url_filters::auto_launch_enabled(store).await,
            None => false,
        };
        let auto_close_tabs = match &self.store {
            Some(store) => browser_url_filters::auto_close_tabs_enabled(store).await,
            None => false,
        };
        let state = self.state.lock().await;
        let extension_path = self.verified_extension_path();
        let extension_ready = extension_path.is_some();
        // A live shared extension connection is the only proof that the default
        // live-retrieval route works. It outranks an unverifiable bundled copy: a
        // user who loaded the extension from another folder still browses fine,
        // and reporting extension_missing there told the model and the UI "no
        // live retrieval" on every turn (#921).
        let shared_connected = state
            .sessions
            .get("shared")
            .and_then(|session| session.client.as_ref())
            .is_some();
        let status = if shared_connected {
            "connected"
        } else if state.startup_error.is_some() {
            "error"
        } else if !extension_ready {
            "extension_missing"
        } else {
            "disconnected"
        };
        let live_retrieval = status == "connected";
        let steps = extension_path.as_ref().map_or_else(Vec::new, |path| {
            vec![
                "Start Wisp Science and keep it running.".to_string(),
                "Open chrome://extensions in the Chrome/Chromium profile Wisp should control."
                    .to_string(),
                "Enable Developer mode.".to_string(),
                format!("Click Load unpacked and select this exact folder: {path}"),
                "Open the Wisp Real Browser Bridge extension popup and confirm Connected to Wisp."
                    .to_string(),
            ]
        });
        let path_instruction = if extension_ready {
            "Copy extension_path character-for-character. Never translate, infer, normalize, or replace any path segment."
        } else {
            "The running Wisp build has no verified bundled extension path. Do not invent a path or claim the extension exists."
        };
        let connected_tabs = state
            .sessions
            .get("shared")
            .map(|slot| slot.tabs.len())
            .unwrap_or(0);
        let bundled_extension_version = bundled_manifest_version(&self.bundled_extension_dir);
        let shared = session_summary(&state, "shared", bundled_extension_version.as_deref());
        let reload_required = shared["reload_required"] == Value::Bool(true);
        let assistant_instruction = match (live_retrieval, reload_required) {
            (true, false) => path_instruction.to_string(),
            (true, true) => format!("{STALE_ASSISTANT_INSTRUCTION} {path_instruction}"),
            (false, _) => format!("{DISCONNECTED_ASSISTANT_INSTRUCTION} {path_instruction}"),
        };
        let reported_extension_version = state
            .sessions
            .get("shared")
            .map(|session| session.meta.extension_version.clone())
            .filter(|version| !version.is_empty())
            .or_else(|| bundled_extension_version.clone());

        json!({
            "status": status,
            "live_retrieval": live_retrieval,
            "code": if live_retrieval { Value::Null } else { json!(BROWSER_DISCONNECTED_CODE) },
            "connected_tabs": connected_tabs,
            "extension_version": reported_extension_version,
            "bundled_extension_version": bundled_extension_version,
            "workspace_limit": project_workspace::MAX_WORKSPACES,
            "required_protocol": REQUIRED_PROTOCOL,
            "reload_required": reload_required,
            "update_required": reload_required,
            "refused_connection": refusal_summary(state.last_refusal.as_ref().filter(|row| row.session == "shared")),

            "sessions": {
                "shared": shared
            },
            "runtime_os": std::env::consts::OS,
            "path_source": if self.managed_extension { "wisp_managed_app_data" } else { "wisp_tauri_resource_dir" },
            "extension_path": extension_path,
            "extension_path_verified": extension_ready,
            "extension_integrity_verified": self.extension_integrity_verified(),
            "extension_update_error": state.extension_update_error.clone(),
            "extension_id": EXTENSION_ORIGIN.trim_start_matches("chrome-extension://"),
            "bridge_endpoint": format!("ws://{BRIDGE_ADDR}"),
            "install_scope": "once_per_browser_profile",
            "assistant_instruction": assistant_instruction,
            "steps": steps,
            "download_automation": {
                "limitation": "GA Web controls web-page tabs. It cannot operate Chrome/Edge toolbar download bubbles or native operating-system Open, Save, and Save As dialogs.",
                "manual_setup_required": true,
                "chrome_settings_url": "chrome://settings/downloads",
                "edge_settings_url": "edge://settings/downloads",
                "setting_to_disable": "Ask where to save each file before downloading",
                "multiple_downloads": {
                    "chrome_settings_url": "chrome://settings/content/automaticDownloads",
                    "edge_settings_url": "edge://settings/content/automaticDownloads",
                    "agent_gate": "Before triggering multiple file downloads, show these browser settings and wait for the user to confirm configuration. Until confirmed, download at most one file.",
                    "recommended_action": "Add only the trusted target site to Allowed to automatically download multiple files. If the browser asks on the site's first batch, choose Allow.",
                    "security_note": "Do not allow automatic multiple downloads for untrusted sites."
                },
                "effect": "Downloads save to the browser's configured default download directory without opening a native location prompt. Authorized filesystem tools may process the saved file afterward."
            },
            "auto_launch_browser": auto_launch,
            "auto_close_tabs": auto_close_tabs,
            "error": state.startup_error
        })
    }

    async fn accept_loop(self: Arc<Self>, listener: TcpListener) {
        self.accept_loop_on(listener, "shared".into()).await;
    }

    async fn accept_loop_on(self: Arc<Self>, listener: TcpListener, session: String) {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let bridge = self.clone();
                    let session = session.clone();
                    tokio::spawn(async move {
                        if let Err(error) = bridge.accept_connection_on(stream, session).await {
                            tracing::warn!(target: "wisp", "browser bridge connection rejected: {error}");
                        }
                    });
                }
                Err(error) => {
                    tracing::warn!(target: "wisp", "browser bridge accept failed: {error}");
                }
            }
        }
    }

    async fn accept_connection(
        self: Arc<Self>,
        stream: TcpStream,
    ) -> Result<(), tokio_tungstenite::tungstenite::Error> {
        self.accept_connection_on(stream, "shared".into()).await
    }

    async fn accept_connection_on(
        self: Arc<Self>,
        stream: TcpStream,
        session: String,
    ) -> Result<(), tokio_tungstenite::tungstenite::Error> {
        self.accept_connection_with_path(stream, session, None)
            .await
    }

    async fn accept_connection_with_path(
        self: Arc<Self>,
        stream: TcpStream,
        session: String,
        connection_path: Option<String>,
    ) -> Result<(), tokio_tungstenite::tungstenite::Error> {
        // The handshake callback is synchronous, so the refused origin is parked
        // here and folded into bridge state once the await returns. Without it a
        // rejected extension is only a log line and the user is told nothing but
        // `connected=false` (#952).
        let refused: Arc<std::sync::Mutex<Option<String>>> = Arc::default();
        let seen = refused.clone();
        let handshake = accept_hdr_async(stream, move |request: &Request, response: Response| {
            let origin = request
                .headers()
                .get("origin")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);
            if allowed_extension_origin(origin.as_deref())
                && workspace_path_matches(connection_path.as_deref(), request.uri().path())
            {
                Ok(response)
            } else {
                if let Ok(mut slot) = seen.lock() {
                    *slot = Some(origin.unwrap_or_default());
                }
                Err(forbidden_response())
            }
        })
        .await;
        let socket = match handshake {
            Ok(socket) => socket,
            Err(error) => {
                let origin = refused.lock().ok().and_then(|slot| slot.clone());
                self.state.lock().await.last_refusal = Some(RefusedConnection {
                    session,
                    origin,
                    reason: error.to_string(),
                });
                return Err(error);
            }
        };
        self.serve_connection_on(socket, session).await;
        Ok(())
    }

    async fn serve_connection(self: Arc<Self>, socket: WebSocketStream<TcpStream>) {
        self.serve_connection_on(socket, "shared".into()).await;
    }

    async fn serve_connection_on(
        self: Arc<Self>,
        socket: WebSocketStream<TcpStream>,
        session: String,
    ) {
        let connection_id = self.next_connection_id.fetch_add(1, Ordering::Relaxed);
        let (mut writer, mut reader) = socket.split();
        let (tx, mut rx) = mpsc::unbounded_channel();
        self.install_client_on(connection_id, tx.clone(), &session)
            .await;
        let writer_task = tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if writer.send(message).await.is_err() {
                    break;
                }
            }
        });

        while let Some(message) = reader.next().await {
            match message {
                Ok(Message::Text(text)) => {
                    self.handle_text_on(connection_id, &session, text.as_str())
                        .await
                }
                Ok(Message::Ping(payload)) => {
                    let _ = tx.send(Message::Pong(payload));
                }
                Ok(Message::Close(_)) | Err(_) => break,
                _ => {}
            }
        }
        writer_task.abort();
        self.disconnect_client_on(connection_id, &session).await;
    }

    async fn install_client(&self, connection_id: u64, tx: mpsc::UnboundedSender<Message>) {
        self.install_client_on(connection_id, tx, "shared").await;
    }

    async fn install_client_on(
        &self,
        connection_id: u64,
        tx: mpsc::UnboundedSender<Message>,
        session: &str,
    ) {
        let mut state = self.state.lock().await;
        if session.starts_with("workspace:")
            && !state
                .workspaces
                .values()
                .any(|instance| instance.identity.lane == session)
        {
            let _ = tx.send(Message::Close(None));
            return;
        }
        let slot = session_slot(&mut state, session);
        fail_pending(slot, "browser extension connection was replaced");
        // Close the superseded socket instead of waiting for TCP to notice.
        // A half-open connection from a previous service worker would
        // otherwise linger ESTABLISHED, and the extension side would keep
        // treating it as live (#1568).
        if let Some(previous) = slot
            .client
            .take()
            .filter(|previous| previous.connection_id != connection_id)
        {
            let _ = previous.tx.send(Message::Close(None));
        }
        slot.client = Some(BridgeClient {
            connection_id,
            session: session.to_string(),
            tx,
        });
        slot.tabs.clear();
        slot.selected_by_frame.clear();
        // Owners survive until the first handshake shows whether this is the
        // same browser run (a service worker restart) or a new one.
        slot.handshaken = false;
    }

    async fn disconnect_client(&self, connection_id: u64) {
        self.disconnect_client_on(connection_id, "shared").await;
    }

    async fn disconnect_client_on(&self, connection_id: u64, session: &str) {
        let mut state = self.state.lock().await;
        if let Some(slot) = state.sessions.get_mut(session) {
            if slot
                .client
                .as_ref()
                .is_some_and(|client| client.connection_id == connection_id)
            {
                slot.client = None;
                slot.tabs.clear();
                slot.selected_by_frame.clear();
                slot.handshaken = false;
                fail_pending(slot, "browser extension disconnected");
            }
        }
    }

    async fn handle_text(&self, connection_id: u64, text: &str) {
        self.handle_text_on(connection_id, "shared", text).await;
    }

    async fn handle_text_on(&self, connection_id: u64, session: &str, text: &str) {
        let Ok(message) = serde_json::from_str::<Value>(text) else {
            return;
        };
        let message_type = message.get("type").and_then(Value::as_str).unwrap_or("");
        if message_type.starts_with("side_") {
            self.forward_side_panel(connection_id, session, message)
                .await;
            return;
        }
        let mut state = self.state.lock().await;
        let Some(slot) = state.sessions.get_mut(session) else {
            return;
        };
        if !slot
            .client
            .as_ref()
            .is_some_and(|client| client.connection_id == connection_id)
        {
            return;
        }
        let retry_auto_close = message_type == "ext_ready";
        match message_type {
            "ext_ready" | "tabs_update" => {
                if message_type == "ext_ready" {
                    let instance = message
                        .get("browser_instance")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    // The extension re-sends ext_ready on every tab event;
                    // only a connection's first one can mean a new browser
                    // run. Without a matching run id, tab and window ids may
                    // have been reused, so ownership only shrinks.
                    if !slot.handshaken {
                        if instance.is_empty() || instance != slot.meta.browser_instance {
                            slot.owners.clear();
                            slot.project_windows.clear();
                        }
                        slot.handshaken = true;
                    }
                    slot.meta.browser_instance = instance;
                    slot.meta.protocol_version = message
                        .get("protocol_version")
                        .and_then(Value::as_i64)
                        .unwrap_or(1);
                    slot.meta.extension_version = message
                        .get("extension_version")
                        .and_then(Value::as_str)
                        .unwrap_or("0.2.1")
                        .to_string();
                    slot.meta.capabilities = message
                        .get("capabilities")
                        .and_then(Value::as_array)
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(Value::as_str)
                                .map(str::to_string)
                                .collect()
                        })
                        .unwrap_or_default();
                    slot.meta.paused = message
                        .get("paused")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                }
                replace_tabs(slot, &message);
            }
            // The extension's keepalive is a JSON text frame (browser JS cannot
            // send protocol-level pings). Answer it so the extension sees
            // inbound traffic on a healthy socket and can tear down one that
            // has gone half-open. Only the registered connection is answered:
            // a replaced socket gets silence, which is exactly the signal the
            // extension uses to drop it.
            "ping" => {
                if let Some(client) = slot.client.as_ref() {
                    let pong = json!({ "type": "pong", "session": session }).to_string();
                    let _ = client.tx.send(Message::Text(pong.into()));
                }
            }
            "result" | "error" => {
                let Some(id) = message.get("id").and_then(Value::as_str) else {
                    return;
                };
                let Some(sender) = slot.pending.remove(id) else {
                    return;
                };
                let result = if message_type == "result" {
                    Ok(parse_bridge_reply(&message))
                } else {
                    Err(errors::from_value(message.get("error")))
                };
                let _ = sender.send(result);
            }
            _ => {}
        }
        drop(state);
        if retry_auto_close {
            self.retry_pending_auto_close().await;
        }
    }

    async fn execute(
        &self,
        requested_tab: Option<i64>,
        code: &str,
        timeout: Duration,
    ) -> Result<BrowserExecution, String> {
        self.execute_on(None, requested_tab, code, timeout).await
    }

    /// Bridge-internal execution (needs-human checks, tests): no tab scope.
    async fn execute_on(
        &self,
        session: Option<&str>,
        requested_tab: Option<i64>,
        code: &str,
        timeout: Duration,
    ) -> Result<BrowserExecution, String> {
        self.execute_in(session, requested_tab, code, timeout, None)
            .await
    }

    /// Execute on a tab inside `scope`. Explicit tabs must already be owned
    /// (tools call `authorize_tab` first), and the default never leaves the
    /// scope. Popups the operated tab opens join the scope.
    async fn execute_in(
        &self,
        session: Option<&str>,
        requested_tab: Option<i64>,
        code: &str,
        timeout: Duration,
        scope: Option<&ToolScope>,
    ) -> Result<BrowserExecution, String> {
        let id = Uuid::new_v4().to_string();
        let (response_tx, response_rx) = oneshot::channel();
        self.ensure_extension(session).await;
        let (session_name, tab_id) = {
            let mut state = self.state.lock().await;
            if let Some(error) = &state.startup_error {
                return Err(self.unavailable_message(error));
            }
            let session_name = resolve_session_name(session)?;
            let slot = session_slot(&mut state, &session_name);
            if slot.meta.paused {
                return Err(errors::structured(
                    errors::USER_CONTROLLING,
                    "user paused browser control from the extension popup",
                    false,
                ));
            }
            let Some(client) = slot.client.clone() else {
                return Err(self.unavailable_message("browser extension is not connected"));
            };
            let tab_id = select_tab(slot, requested_tab, scope)?;
            slot.selected_by_frame
                .insert(selection_key(scope).to_string(), tab_id);
            slot.pending.insert(id.clone(), response_tx);
            let payload = request_payload(&id, Some(tab_id), code, timeout);
            if client.tx.send(Message::Text(payload.into())).is_err() {
                if let Some(slot) = state.sessions.get_mut(client.session.as_str()) {
                    slot.pending.remove(&id);
                }
                return Err("browser extension disconnected before the request was sent".into());
            }
            (session_name, tab_id)
        };

        match tokio::time::timeout(timeout, response_rx).await {
            Ok(Ok(Ok(reply))) => {
                let adopted_tabs = match scope {
                    Some(scope) => {
                        self.adopt_popups(&session_name, scope, tab_id, &reply.new_tabs)
                            .await
                    }
                    None => Vec::new(),
                };
                Ok(BrowserExecution {
                    session: session_name,
                    tab_id,
                    value: reply.value,
                    ready: reply.ready,
                    wait: reply.wait,
                    adopted_tabs,
                })
            }
            Ok(Ok(Err(error))) => Err(error),
            Ok(Err(_)) => Err("browser extension disconnected before returning a result".into()),
            Err(_) => {
                self.state
                    .lock()
                    .await
                    .sessions
                    .values_mut()
                    .for_each(|slot| {
                        slot.pending.remove(&id);
                    });
                Err(format!(
                    "browser execution timed out after {} ms",
                    timeout.as_millis()
                ))
            }
        }
    }

    /// Send a control command that does not target an existing tab (e.g. open a
    /// new tab). Unlike `execute`, this never requires an HTTP(S) tab to exist,
    /// so it can bootstrap browsing from an empty profile.
    async fn send_command(&self, code: String, timeout: Duration) -> Result<BridgeReply, String> {
        self.send_command_on(None, code, timeout).await
    }

    async fn send_command_on(
        &self,
        session: Option<&str>,
        code: String,
        timeout: Duration,
    ) -> Result<BridgeReply, String> {
        self.send_command_on_named(session, code, timeout)
            .await
            .map(|(_, reply)| reply)
    }

    async fn send_command_on_named(
        &self,
        session: Option<&str>,
        code: String,
        timeout: Duration,
    ) -> Result<(String, BridgeReply), String> {
        self.ensure_extension(session).await;
        let id = Uuid::new_v4().to_string();
        let (response_tx, response_rx) = oneshot::channel();
        let session_name = {
            let mut state = self.state.lock().await;
            if let Some(error) = &state.startup_error {
                return Err(self.unavailable_message(error));
            }
            let session_name = resolve_session_name(session)?;
            let slot = session_slot(&mut state, &session_name);
            if slot.meta.paused {
                return Err(errors::structured(
                    errors::USER_CONTROLLING,
                    "user paused browser control from the extension popup",
                    false,
                ));
            }
            let Some(client) = slot.client.clone() else {
                return Err(self.unavailable_message("browser extension is not connected"));
            };
            slot.pending.insert(id.clone(), response_tx);
            let payload = request_payload(&id, None, &code, timeout);
            if client.tx.send(Message::Text(payload.into())).is_err() {
                if let Some(slot) = state.sessions.get_mut(client.session.as_str()) {
                    slot.pending.remove(&id);
                }
                return Err("browser extension disconnected before the request was sent".into());
            }
            session_name
        };

        match tokio::time::timeout(timeout, response_rx).await {
            Ok(Ok(Ok(value))) => Ok((session_name, value)),
            Ok(Ok(Err(error))) => Err(error),
            Ok(Err(_)) => Err("browser extension disconnected before returning a result".into()),
            Err(_) => {
                self.state
                    .lock()
                    .await
                    .sessions
                    .values_mut()
                    .for_each(|slot| {
                        slot.pending.remove(&id);
                    });
                Err(format!(
                    "browser command timed out after {} ms",
                    timeout.as_millis()
                ))
            }
        }
    }

    async fn open_tab(&self, url: &str, active: bool) -> Result<BridgeReply, String> {
        self.open_tab_on(None, url, active, None)
            .await
            .map(|(_, reply, _)| reply)
    }

    /// Open a tab. With a scope, the tab opens in the project's dedicated
    /// window (created and bound on first use, rebuilt if the user closed it)
    /// and belongs to the calling conversation. Returns a note for the model
    /// when the fixed window could not be honored.
    async fn open_tab_on(
        &self,
        session: Option<&str>,
        url: &str,
        active: bool,
        scope: Option<&ToolScope>,
    ) -> Result<(String, BridgeReply, Option<String>), String> {
        let Some(scope) = scope else {
            let (session_name, reply) = self
                .send_tab_create(session, url, active, TabPlacement::Current)
                .await?;
            self.remember_tab_value(&session_name, &reply.value).await;
            return Ok((session_name, reply, None));
        };
        if !self.lane_supports(&scope.lane, "window_binding").await {
            let (session_name, reply) = self
                .send_tab_create(session, url, active, TabPlacement::Current)
                .await?;
            self.remember_tab_value(&session_name, &reply.value).await;
            self.adopt_created_tab(&session_name, scope, &reply.value)
                .await;
            return Ok((session_name, reply, Some(WINDOW_BINDING_UNAVAILABLE.into())));
        }
        let mut bind_guard = None;
        let mut bound = self.bound_window(scope).await;
        if bound.is_none() {
            bind_guard = Some(self.window_bind_lock.lock().await);
            bound = self.bound_window(scope).await;
        }
        let mut note = None;
        let placement = bound.map_or(TabPlacement::NewWindow, TabPlacement::Window);
        let (session_name, reply) =
            match self.send_tab_create(session, url, active, placement).await {
                Err(error) if bound.is_some() && error.contains(WINDOW_GONE_CODE) => {
                    // Never fall back to whatever window has focus: rebuild a
                    // window for the same project and bind that instead.
                    self.unbind_window(scope, bound).await;
                    if bind_guard.is_none() {
                        bind_guard = Some(self.window_bind_lock.lock().await);
                    }
                    let rebound = self.bound_window(scope).await;
                    note = Some(WINDOW_REBOUND_NOTE.to_string());
                    let placement = rebound.map_or(TabPlacement::NewWindow, TabPlacement::Window);
                    self.send_tab_create(session, url, active, placement)
                        .await?
                }
                other => other?,
            };
        if let Some(window_id) = parse_created_tab(&reply.value).and_then(|tab| tab.window_id) {
            self.bind_window(scope, window_id).await;
        }
        drop(bind_guard);
        self.remember_tab_value(&session_name, &reply.value).await;
        self.adopt_created_tab(&session_name, scope, &reply.value)
            .await;
        Ok((session_name, reply, note))
    }

    async fn send_tab_create(
        &self,
        session: Option<&str>,
        url: &str,
        active: bool,
        placement: TabPlacement,
    ) -> Result<(String, BridgeReply), String> {
        let mut command =
            json!({ "cmd": "tabs", "method": "create", "url": url, "active": active });
        match placement {
            TabPlacement::Current => {}
            TabPlacement::Window(window_id) => command["windowId"] = json!(window_id),
            TabPlacement::NewWindow => command["newWindow"] = json!(true),
        }
        self.send_command_on_named(
            session,
            command.to_string(),
            Duration::from_millis(DEFAULT_TIMEOUT_MS),
        )
        .await
    }

    async fn lane_supports(&self, lane: &str, capability: &str) -> bool {
        self.state
            .lock()
            .await
            .sessions
            .get(lane)
            .is_some_and(|slot| slot.meta.capabilities.iter().any(|item| item == capability))
    }

    async fn bound_window(&self, scope: &ToolScope) -> Option<i64> {
        self.state
            .lock()
            .await
            .sessions
            .get(&scope.lane)
            .and_then(|slot| slot.project_windows.get(&scope.project_id).copied())
    }

    async fn bind_window(&self, scope: &ToolScope, window_id: i64) {
        let mut state = self.state.lock().await;
        session_slot(&mut state, &scope.lane)
            .project_windows
            .insert(scope.project_id.clone(), window_id);
    }

    /// Forget a binding only if it still names the window that disappeared,
    /// so a concurrent rebind is never undone.
    async fn unbind_window(&self, scope: &ToolScope, gone: Option<i64>) {
        let mut state = self.state.lock().await;
        if let Some(slot) = state.sessions.get_mut(&scope.lane) {
            if slot.project_windows.get(&scope.project_id).copied() == gone {
                slot.project_windows.remove(&scope.project_id);
            }
        }
    }

    async fn adopt_created_tab(&self, session: &str, scope: &ToolScope, value: &Value) {
        let Some(tab) = parse_created_tab(value) else {
            return;
        };
        let mut state = self.state.lock().await;
        let slot = session_slot(&mut state, session);
        slot.owners.insert(tab.id, scope.owner());
    }

    /// Adopt only tabs the operated tab itself opened (`openerTabId`): a tab
    /// the user or another conversation created meanwhile stays out of scope.
    async fn adopt_popups(
        &self,
        session: &str,
        scope: &ToolScope,
        opener: i64,
        new_tabs: &[NewTab],
    ) -> Vec<i64> {
        let adopted: Vec<i64> = new_tabs
            .iter()
            .filter(|tab| tab.opener == Some(opener))
            .map(|tab| tab.id)
            .collect();
        if adopted.is_empty() {
            return adopted;
        }
        let mut state = self.state.lock().await;
        let slot = session_slot(&mut state, session);
        for id in &adopted {
            if !slot.owners.contains_key(id) {
                slot.owners.insert(*id, scope.owner());
            }
        }
        adopted
    }

    /// Make sure this scope may drive `tab_id`, asking the user when the tab
    /// exists but belongs to someone else. Approving moves the tab into this
    /// conversation's scope; an id unknown to the lane is left for
    /// `select_tab` to report.
    async fn authorize_tab(
        &self,
        env: &dyn ToolEnv,
        scope: &ToolScope,
        tab_id: i64,
    ) -> Result<(), String> {
        let prompt = {
            let state = self.state.lock().await;
            let Some(slot) = state.sessions.get(&scope.lane) else {
                return Ok(());
            };
            let Some(tab) = slot.tabs.get(&tab_id) else {
                return Ok(());
            };
            if scope.owns(slot, tab_id) {
                return Ok(());
            }
            grant_prompt(tab, slot.owners.get(&tab_id), scope)
        };
        if !env.confirm(&prompt).await {
            return Err(format!(
                "The user did not allow this conversation to control browser tab {tab_id}. Do not retry it; open your own tab with web_open_tab instead."
            ));
        }
        let mut state = self.state.lock().await;
        let slot = session_slot(&mut state, &scope.lane);
        if !slot.tabs.contains_key(&tab_id) {
            return Err(format!(
                "browser tab {tab_id} closed while waiting for approval; call web_scan with tabs_only=true"
            ));
        }
        slot.owners.insert(tab_id, scope.owner());
        Ok(())
    }

    /// Resolve `switch_tab_id` for a scoped tool: a numeric id, or "active"
    /// to ask for the tab the user is looking at. Either way an out-of-scope
    /// tab goes through the approval prompt before any command reaches it.
    async fn tool_tab(
        &self,
        args: &Value,
        env: &dyn ToolEnv,
        session: Option<&str>,
        scope: Option<&ToolScope>,
    ) -> Result<Option<i64>, String> {
        let requested = if wants_active_tab(args) {
            Some(self.user_active_tab(session).await?)
        } else {
            tab_id_arg(args)?
        };
        if let (Some(tab_id), Some(scope)) = (requested, scope) {
            self.authorize_tab(env, scope, tab_id).await?;
        }
        Ok(requested)
    }

    /// The tab the user most likely means by "this page": an active tab
    /// outside Wisp's own project windows when there is one.
    async fn user_active_tab(&self, session: Option<&str>) -> Result<i64, String> {
        let session_name = resolve_session_name(session)?;
        let state = self.state.lock().await;
        let Some(slot) = state.sessions.get(&session_name) else {
            return Err(self.unavailable_message("browser extension is not connected"));
        };
        let wisp_windows: HashSet<i64> = slot.project_windows.values().copied().collect();
        let active = || slot.tabs.values().filter(|tab| tab.active);
        active()
            .find(|tab| !tab.window_id.is_some_and(|id| wisp_windows.contains(&id)))
            .or_else(|| active().next())
            .map(|tab| tab.id)
            .ok_or_else(|| "no active HTTP(S) tab is open in the browser".into())
    }

    /// Tabs this scope may see. Unscoped callers see the whole lane.
    async fn tabs_in(
        &self,
        session: Option<&str>,
        scope: Option<&ToolScope>,
    ) -> Result<Vec<BrowserTab>, String> {
        let tabs = self.tabs_on(session).await?;
        let Some(scope) = scope else {
            return Ok(tabs);
        };
        let state = self.state.lock().await;
        let Some(slot) = state.sessions.get(&scope.lane) else {
            return Ok(Vec::new());
        };
        Ok(tabs
            .into_iter()
            .filter(|tab| scope.owns(slot, tab.id))
            .collect())
    }

    /// Reject embedded tab references a JSON command would act on outside
    /// this scope (`tabs.close`, `tabs.switch`, `cdp.tabId`), and CDP domains
    /// that reach other targets or windows. Mirrors how the extension reads
    /// the command, so a value it would act on cannot slip past as "unknown".
    async fn refuse_if_out_of_scope(&self, scope: &ToolScope, script: &str) -> Result<(), String> {
        let ids = scoped_tab_refs(script)?;
        if ids.is_empty() {
            return Ok(());
        }
        let state = self.state.lock().await;
        let slot = state.sessions.get(&scope.lane);
        for id in ids {
            if !slot.is_some_and(|slot| scope.owns(slot, id)) {
                return Err(out_of_scope_message(id));
            }
        }
        Ok(())
    }

    async fn owned_ids(&self, scope: &ToolScope) -> HashSet<i64> {
        let state = self.state.lock().await;
        state
            .sessions
            .get(&scope.lane)
            .map(|slot| {
                slot.owners
                    .iter()
                    .filter(|(id, _)| scope.owns(slot, **id))
                    .map(|(id, _)| *id)
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn require_capability(
        &self,
        session: Option<&str>,
        capability: &str,
    ) -> Result<String, String> {
        self.ensure_extension(session).await;
        let state = self.state.lock().await;
        if let Some(error) = &state.startup_error {
            return Err(self.unavailable_message(error));
        }
        let session_name = resolve_session_name(session)?;
        let Some(slot) = state.sessions.get(&session_name) else {
            return Err(self.unavailable_message("browser extension is not connected"));
        };
        if slot.client.is_none() {
            return Err(self.unavailable_message("browser extension is not connected"));
        }
        let has_capability = slot.meta.capabilities.iter().any(|item| item == capability);
        if slot.meta.protocol_version < REQUIRED_PROTOCOL || !has_capability {
            let version = if slot.meta.extension_version.is_empty() {
                "unknown".to_string()
            } else {
                slot.meta.extension_version.clone()
            };
            let bundled_version = bundled_manifest_version(&self.bundled_extension_dir)
                .unwrap_or_else(|| "bundled version".into());
            return Err(errors::structured(
                errors::EXTENSION_STALE,
                &format!(
                    "connected extension {version} (protocol {}) does not provide '{capability}'. Call browser_setup with action=update_extension to prepare and load Wisp Real Browser Bridge {bundled_version}. Do not pretend the new tool exists.",
                    slot.meta.protocol_version,
                ),
                false,
            ));
        }
        Ok(session_name)
    }

    async fn require_chat_capability(&self, session: Option<&str>) -> Result<String, String> {
        match self.require_capability(session, "chat_turn").await {
            Ok(name) => Ok(name),
            Err(chat_error) => match self.require_capability(session, "chatgpt_turn").await {
                Ok(name) => Ok(name),
                Err(_) => Err(chat_error),
            },
        }
    }

    async fn wait_for_session(&self, session: &str, wait: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            if self.session_connected(session).await {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    async fn session_connected(&self, session: &str) -> bool {
        self.state
            .lock()
            .await
            .sessions
            .get(session)
            .and_then(|slot| slot.client.as_ref())
            .is_some()
    }

    async fn tabs(&self) -> Result<Vec<BrowserTab>, String> {
        self.ensure_extension(None).await;
        let state = self.state.lock().await;
        if let Some(error) = &state.startup_error {
            return Err(self.unavailable_message(error));
        }
        let session_name = resolve_session_name(None)?;
        let Some(slot) = state.sessions.get(&session_name) else {
            return Err(self.unavailable_message("browser extension is not connected"));
        };
        if slot.client.is_none() {
            return Err(self.unavailable_message("browser extension is not connected"));
        }
        Ok(slot.tabs.values().cloned().collect())
    }

    async fn tabs_on(&self, session: Option<&str>) -> Result<Vec<BrowserTab>, String> {
        self.ensure_extension(session).await;
        let state = self.state.lock().await;
        if let Some(error) = &state.startup_error {
            return Err(self.unavailable_message(error));
        }
        let session_name = resolve_session_name(session)?;
        let Some(slot) = state.sessions.get(&session_name) else {
            return Err(self.unavailable_message("browser extension is not connected"));
        };
        if slot.client.is_none() {
            return Err(self.unavailable_message("browser extension is not connected"));
        }
        Ok(slot.tabs.values().cloned().collect())
    }

    async fn client_connected(&self) -> bool {
        self.state
            .lock()
            .await
            .sessions
            .values()
            .any(|slot| slot.client.is_some())
    }

    /// If the extension is down and auto-launch is on, start the user's
    /// Chrome/Chromium/Edge so the already-installed unpacked extension can
    /// reconnect. Never used from tests (`can_launch` is false on `new()`).
    async fn ensure_extension(&self, session: Option<&str>) {
        self.ensure_extension_with(session, || spawn_user_browser(None), AUTO_LAUNCH_WAIT)
            .await;
    }

    async fn ensure_extension_with(
        &self,
        session: Option<&str>,
        launch: impl FnOnce() -> Result<(), String>,
        wait: Duration,
    ) {
        // Auto-launch owns only the default shared profile. Workspace mode is
        // opt-in and starts exclusively through browser_setup.start_workspace.
        if session.is_some_and(|name| name != "shared") || self.session_connected("shared").await {
            return;
        }
        if !self.can_launch {
            return;
        }
        if self.state.lock().await.startup_error.is_some() {
            return;
        }
        let enabled = match &self.store {
            Some(store) => browser_url_filters::auto_launch_enabled(store).await,
            None => false,
        };
        if !enabled {
            return;
        }
        let _guard = self.launch_lock.lock().await;
        if self.session_connected("shared").await {
            return;
        }
        if let Err(error) = launch() {
            tracing::warn!(target: "wisp", "browser auto-launch failed: {error}");
            return;
        }
        let deadline = tokio::time::Instant::now() + wait;
        while tokio::time::Instant::now() < deadline {
            if self.session_connected("shared").await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    fn unavailable_message(&self, reason: &str) -> String {
        let setup = match self.verified_extension_path() {
            Some(path) => format!(
                "real-browser bridge unavailable: {reason}. In Chrome/Chromium open chrome://extensions, enable Developer mode, and Load unpacked from this exact native {} path: '{path}'. Keep Wisp running; the extension connects only to {BRIDGE_ADDR}.",
                std::env::consts::OS
            ),
            None => format!(
                "real-browser bridge unavailable: {reason}. This Wisp build has no verified bundled browser extension; do not infer an installation path."
            ),
        };
        format!("{setup} {BROWSER_DISCONNECTED_MARKER}. {DISCONNECTED_ASSISTANT_INSTRUCTION}")
    }

    fn verified_extension_path(&self) -> Option<String> {
        if !self.extension_integrity_verified() {
            return None;
        }
        let dir = dunce::canonicalize(&self.extension_dir).ok()?;
        Some(dir.display().to_string())
    }

    async fn remember_tab_value(&self, session: &str, value: &Value) {
        let Some(tab) = parse_created_tab(value) else {
            return;
        };
        let mut state = self.state.lock().await;
        session_slot(&mut state, session).tabs.insert(tab.id, tab);
    }

    /// Track a tab Wisp opened this turn for cleanup and, with a scope, make
    /// the calling conversation its owner.
    async fn record_opened_tab(
        &self,
        turn_id: &str,
        frame_id: &str,
        session: &str,
        value: &Value,
        scope: Option<&ToolScope>,
    ) {
        let Some(tab) = parse_created_tab(value) else {
            return;
        };
        self.remember_tab_value(session, value).await;
        if let Some(scope) = scope {
            self.adopt_created_tab(session, scope, value).await;
        }
        let mut ledgers = self.turn_ledgers.lock().await;
        let ledger = ledgers
            .entry(turn_id.to_string())
            .or_insert_with(|| TurnTabLedger {
                turn_id: turn_id.to_string(),
                frame_id: frame_id.to_string(),
                tabs: Vec::new(),
            });
        if ledger.frame_id.is_empty() && !frame_id.is_empty() {
            ledger.frame_id = frame_id.to_string();
        }
        if ledger
            .tabs
            .iter()
            .any(|existing| existing.session == session && existing.tab_id == tab.id)
        {
            return;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);
        ledger.tabs.push(TrackedTab {
            session: session.to_string(),
            tab_id: tab.id,
            initial_url: tab.url.clone(),
            url: tab.url,
            title: tab.title,
            created_at: now,
        });
    }

    async fn unrecord_tabs(&self, session: &str, ids: &[i64]) {
        if ids.is_empty() {
            return;
        }
        let id_set: HashSet<i64> = ids.iter().copied().collect();
        if let Some(slot) = self.state.lock().await.sessions.get_mut(session) {
            slot.owners.retain(|id, _| !id_set.contains(id));
            slot.selected_by_frame.retain(|_, id| !id_set.contains(id));
        }
        let mut ledgers = self.turn_ledgers.lock().await;
        for ledger in ledgers.values_mut() {
            ledger
                .tabs
                .retain(|tab| !(tab.session == session && id_set.contains(&tab.tab_id)));
        }
        let mut pending = self.pending_cleanups.lock().await;
        for cleanup in pending.values_mut() {
            cleanup
                .prompt
                .tabs
                .retain(|tab| !(tab.session == session && id_set.contains(&tab.tab_id)));
        }
        pending.retain(|_, cleanup| !cleanup.prompt.tabs.is_empty());
        drop(ledgers);
        drop(pending);
        self.persist_pending().await;
        let mut human = self.needs_human.lock().await;
        let before = human.len();
        human.retain(|(session_name, tab_id), _| {
            !(session_name == session && id_set.contains(tab_id))
        });
        let changed = human.len() != before;
        drop(human);
        if changed {
            self.persist_needs_human().await;
            self.emit_needs_human().await;
        }
    }

    fn still_open_tabs(state: &BridgeState, tabs: &[TrackedTab]) -> Vec<TrackedTab> {
        tabs.iter()
            .filter_map(|tab| {
                let Some(slot) = state.sessions.get(&tab.session) else {
                    return Some(tab.clone());
                };
                if slot.client.is_none() {
                    return Some(tab.clone());
                }
                let live = slot.tabs.get(&tab.tab_id)?;
                Some(TrackedTab {
                    url: live.url.clone(),
                    title: live.title.clone(),
                    ..tab.clone()
                })
            })
            .collect()
    }

    async fn close_tabs_on(&self, session: &str, ids: &[i64]) -> Result<Vec<i64>, String> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let code = json!({ "cmd": "tabs", "method": "close", "tabIds": ids }).to_string();
        let reply = self
            .send_command_on(
                Some(session),
                code,
                Duration::from_millis(DEFAULT_TIMEOUT_MS),
            )
            .await?;
        let closed = reply
            .value
            .get("closed")
            .and_then(Value::as_array)
            .map(|rows| rows.iter().filter_map(Value::as_i64).collect::<Vec<_>>())
            .unwrap_or_else(|| ids.to_vec());
        {
            let mut state = self.state.lock().await;
            if let Some(slot) = state.sessions.get_mut(session) {
                for id in &closed {
                    slot.tabs.remove(id);
                }
            }
        }
        self.unrecord_tabs(session, &closed).await;
        Ok(closed)
    }

    async fn close_items(&self, items: &[BrowserTabCleanupItem]) -> Result<Vec<i64>, String> {
        let mut by_session: BTreeMap<String, Vec<i64>> = BTreeMap::new();
        for item in items {
            by_session
                .entry(item.session.clone())
                .or_default()
                .push(item.tab_id);
        }
        let mut closed = Vec::new();
        let mut last_error = None;
        for (session, ids) in by_session {
            match self.close_tabs_on(&session, &ids).await {
                Ok(mut ids) => closed.append(&mut ids),
                Err(error) => last_error = Some(error),
            }
        }
        if closed.is_empty() {
            if let Some(error) = last_error {
                return Err(error);
            }
        }
        Ok(closed)
    }

    fn prompt_from_tabs(
        turn_id: &str,
        frame_id: &str,
        tabs: &[TrackedTab],
    ) -> BrowserTabCleanupPrompt {
        BrowserTabCleanupPrompt {
            turn_id: turn_id.to_string(),
            frame_id: frame_id.to_string(),
            tabs: tabs.iter().map(TrackedTab::to_item).collect(),
        }
    }

    async fn stash_pending(&self, prompt: BrowserTabCleanupPrompt, auto_close: bool) {
        if prompt.tabs.is_empty() {
            return;
        }
        let mut pending = self.pending_cleanups.lock().await;
        pending.insert(
            prompt.turn_id.clone(),
            PendingCleanup { prompt, auto_close },
        );
        drop(pending);
        self.persist_pending().await;
    }

    async fn persist_pending(&self) {
        let Some(store) = &self.store else {
            return;
        };
        let pending: Vec<PendingCleanup> = self
            .pending_cleanups
            .lock()
            .await
            .values()
            .cloned()
            .collect();
        let json = serde_json::to_string(&pending).unwrap_or_else(|_| "[]".into());
        let _ = store.set_setting(PENDING_CLEANUP_KEY, &json).await;
    }

    async fn load_pending_cleanups(&self) {
        let Some(store) = &self.store else {
            return;
        };
        let Some(raw) = store.get_setting(PENDING_CLEANUP_KEY).await.ok().flatten() else {
            return;
        };
        let Ok(rows) = serde_json::from_str::<Vec<PendingCleanup>>(&raw) else {
            return;
        };
        let mut pending = self.pending_cleanups.lock().await;
        for mut row in rows {
            // Workspace tab ids belong to a previous process generation.
            row.prompt.tabs.retain(|tab| tab.session == "shared");
            if !row.prompt.turn_id.is_empty() && !row.prompt.tabs.is_empty() {
                pending.insert(row.prompt.turn_id.clone(), row);
            }
        }
    }

    pub(crate) async fn list_pending_cleanups(&self) -> Vec<BrowserTabCleanupPrompt> {
        self.pending_cleanups
            .lock()
            .await
            .values()
            .map(|row| row.prompt.clone())
            .collect()
    }

    async fn project_pending_cleanups(
        &self,
        store: &Store,
        project_id: Option<&str>,
    ) -> Result<Vec<BrowserTabCleanupPrompt>, String> {
        let mut prompts = Vec::new();
        for prompt in self.list_pending_cleanups().await {
            if browser_frame_belongs_to_project(store, &prompt.frame_id, project_id).await? {
                prompts.push(prompt);
            }
        }
        Ok(prompts)
    }

    pub(crate) async fn complete_turn(&self, turn_id: &str) -> TabCleanupAction {
        // Occupancy outlives individual tool calls; release even when this
        // turn opened no tabs so a foreign project can acquire next.
        self.release_turn(turn_id);
        let ledger = self.turn_ledgers.lock().await.remove(turn_id);
        let Some(ledger) = ledger else {
            return TabCleanupAction::None;
        };
        let tabs = {
            let state = self.state.lock().await;
            Self::still_open_tabs(&state, &ledger.tabs)
        };
        if tabs.is_empty() {
            return TabCleanupAction::None;
        }
        let auto_close = match &self.store {
            Some(store) => browser_url_filters::auto_close_tabs_enabled(store).await,
            None => false,
        };
        let held_keys: HashSet<(String, i64)> =
            self.needs_human.lock().await.keys().cloned().collect();
        let held_this_turn = tabs
            .iter()
            .any(|tab| held_keys.contains(&(tab.session.clone(), tab.tab_id)));
        let closeable: Vec<TrackedTab> = tabs
            .into_iter()
            .filter(|tab| !held_keys.contains(&(tab.session.clone(), tab.tab_id)))
            .collect();
        if held_this_turn {
            self.emit_needs_human().await;
        }
        if closeable.is_empty() {
            return TabCleanupAction::None;
        }
        let prompt = Self::prompt_from_tabs(&ledger.turn_id, &ledger.frame_id, &closeable);
        if auto_close {
            let items: Vec<BrowserTabCleanupItem> =
                closeable.iter().map(TrackedTab::to_item).collect();
            match self.close_items(&items).await {
                Ok(_) => TabCleanupAction::Closed,
                Err(_) => {
                    self.stash_pending(prompt.clone(), true).await;
                    TabCleanupAction::Prompt(prompt)
                }
            }
        } else {
            self.stash_pending(prompt.clone(), false).await;
            TabCleanupAction::Prompt(prompt)
        }
    }

    pub(crate) async fn confirm_cleanup(
        &self,
        turn_id: &str,
        selected: &[BrowserTabCleanupItem],
    ) -> Result<Vec<i64>, String> {
        let pending = self.pending_cleanups.lock().await.remove(turn_id);
        let Some(pending) = pending else {
            return Err("no pending browser tab cleanup for this turn".into());
        };
        let allowed: HashSet<(String, i64)> = pending
            .prompt
            .tabs
            .iter()
            .map(|tab| (tab.session.clone(), tab.tab_id))
            .collect();
        let to_close: Vec<BrowserTabCleanupItem> = selected
            .iter()
            .filter(|tab| allowed.contains(&(tab.session.clone(), tab.tab_id)))
            .cloned()
            .collect();
        match self.close_items(&to_close).await {
            Ok(closed) => {
                self.persist_pending().await;
                Ok(closed)
            }
            Err(error) => {
                self.pending_cleanups
                    .lock()
                    .await
                    .insert(turn_id.to_string(), pending);
                self.persist_pending().await;
                Err(error)
            }
        }
    }

    pub(crate) async fn dismiss_cleanup(&self, turn_id: &str) {
        self.pending_cleanups.lock().await.remove(turn_id);
        self.persist_pending().await;
    }

    pub(crate) async fn set_needs_human_sink(
        &self,
        tx: mpsc::UnboundedSender<Vec<BrowserNeedsHumanTab>>,
    ) {
        *self.needs_human_tx.lock().await = Some(tx);
    }

    pub(crate) async fn set_side_panel_sink(
        &self,
        tx: mpsc::UnboundedSender<side_panel::SideRequest>,
    ) {
        *self.side_panel_tx.lock().await = Some(tx);
    }

    /// Hand a side panel message to the app together with the sending
    /// connection, so the turn's events return to the extension that asked.
    async fn forward_side_panel(&self, connection_id: u64, session: &str, message: Value) {
        let reply = self
            .state
            .lock()
            .await
            .sessions
            .get(session)
            .and_then(|slot| slot.client.as_ref())
            .filter(|client| client.connection_id == connection_id)
            .map(|client| client.tx.clone());
        let sink = self.side_panel_tx.lock().await.clone();
        if let (Some(reply), Some(sink)) = (reply, sink) {
            let _ = sink.send(side_panel::SideRequest { reply, message });
        }
    }

    pub(crate) async fn list_needs_human(&self) -> BrowserNeedsHumanPrompt {
        BrowserNeedsHumanPrompt {
            tabs: self.snapshot_needs_human().await,
        }
    }

    async fn snapshot_needs_human(&self) -> Vec<BrowserNeedsHumanTab> {
        let mut tabs: Vec<BrowserNeedsHumanTab> =
            self.needs_human.lock().await.values().cloned().collect();
        tabs.sort_by(|left, right| {
            left.session
                .cmp(&right.session)
                .then(left.tab_id.cmp(&right.tab_id))
        });
        tabs
    }

    async fn emit_needs_human(&self) {
        let tabs = self.snapshot_needs_human().await;
        if let Some(tx) = self.needs_human_tx.lock().await.as_ref() {
            let _ = tx.send(tabs);
        }
    }

    async fn persist_needs_human(&self) {
        let Some(store) = &self.store else {
            return;
        };
        let tabs = self.snapshot_needs_human().await;
        let json = serde_json::to_string(&tabs).unwrap_or_else(|_| "[]".into());
        let _ = store.set_setting(PENDING_NEEDS_HUMAN_KEY, &json).await;
    }

    async fn load_pending_needs_human(&self) {
        let Some(store) = &self.store else {
            return;
        };
        let Some(raw) = store
            .get_setting(PENDING_NEEDS_HUMAN_KEY)
            .await
            .ok()
            .flatten()
        else {
            return;
        };
        let Ok(tabs) = serde_json::from_str::<Vec<BrowserNeedsHumanTab>>(&raw) else {
            return;
        };
        let mut map = self.needs_human.lock().await;
        for tab in tabs {
            if tab.tab_id != 0 && tab.session == "shared" {
                map.insert((tab.session.clone(), tab.tab_id), tab);
            }
        }
    }

    async fn apply_human_verification(
        &self,
        session: &str,
        tab_id: i64,
        page: &Value,
        frame_id: &str,
        turn_id: &str,
    ) {
        match human_verification_handoff(page) {
            Some(handoff) => {
                let reason = handoff
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("captcha_challenge")
                    .to_string();
                let url = page
                    .get("url")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let title = page
                    .get("title")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let mut map = self.needs_human.lock().await;
                let key = (session.to_string(), tab_id);
                let inserted = !map.contains_key(&key);
                let turn_changed = map
                    .get(&key)
                    .is_some_and(|existing| !turn_id.is_empty() && existing.turn_id != turn_id);
                let entry = map.entry(key).or_insert_with(|| BrowserNeedsHumanTab {
                    session: session.to_string(),
                    tab_id,
                    url: url.clone(),
                    title: title.clone(),
                    reason: reason.clone(),
                    frame_id: frame_id.to_string(),
                    turn_id: turn_id.to_string(),
                });
                if !url.is_empty() {
                    entry.url = url;
                }
                if !title.is_empty() {
                    entry.title = title;
                }
                entry.reason = reason;
                if entry.frame_id.is_empty() && !frame_id.is_empty() {
                    entry.frame_id = frame_id.to_string();
                }
                if !turn_id.is_empty() {
                    entry.turn_id = turn_id.to_string();
                }
                drop(map);
                self.persist_needs_human().await;
                if inserted || turn_changed {
                    self.emit_needs_human().await;
                }
            }
            None => {
                let removed = self
                    .needs_human
                    .lock()
                    .await
                    .remove(&(session.to_string(), tab_id))
                    .is_some();
                if removed {
                    self.persist_needs_human().await;
                    self.emit_needs_human().await;
                }
            }
        }
    }

    async fn refuse_if_needs_human(
        &self,
        session: Option<&str>,
        requested_tab: Option<i64>,
        script: &str,
        scope: Option<&ToolScope>,
    ) -> Result<(), String> {
        let pending: HashSet<(String, i64)> =
            self.needs_human.lock().await.keys().cloned().collect();
        if pending.is_empty() {
            return Ok(());
        }
        let state = self.state.lock().await;
        let session_name = match resolve_session_name(session) {
            Ok(name) => name,
            Err(_) => return Ok(()),
        };
        if let Some(ids) = close_ids_from_script(script) {
            if ids
                .iter()
                .any(|id| pending.contains(&(session_name.clone(), *id)))
            {
                return Err(needs_human_block_message());
            }
        }
        if script_allowed_during_needs_human(script) {
            return Ok(());
        }
        let Some(slot) = state.sessions.get(&session_name) else {
            return Ok(());
        };
        let Ok(tab_id) = select_tab(slot, requested_tab, scope) else {
            return Ok(());
        };
        if pending.contains(&(session_name, tab_id)) {
            return Err(needs_human_block_message());
        }
        Ok(())
    }

    /// The pending verification tabs a window bound to `project_id` may act
    /// on. Ownership comes from the bridge's own record of each tab, never
    /// from the frame id the UI sent back. An empty request means all of the
    /// project's pending tabs.
    async fn project_needs_human_targets(
        &self,
        store: &Store,
        project_id: Option<&str>,
        requested: &[BrowserNeedsHumanTab],
    ) -> Result<Vec<BrowserNeedsHumanTab>, String> {
        let candidates: Vec<BrowserNeedsHumanTab> = if requested.is_empty() {
            self.snapshot_needs_human().await
        } else {
            let recorded = self.needs_human.lock().await;
            requested
                .iter()
                .filter_map(|tab| recorded.get(&(tab.session.clone(), tab.tab_id)).cloned())
                .collect()
        };
        let mut targets = Vec::new();
        for tab in candidates {
            if browser_frame_belongs_to_project(store, &tab.frame_id, project_id).await? {
                targets.push(tab);
            }
        }
        Ok(targets)
    }

    pub(crate) async fn confirm_needs_human_for_project(
        &self,
        store: &Store,
        project_id: Option<&str>,
        requested: &[BrowserNeedsHumanTab],
    ) -> Result<BrowserNeedsHumanConfirmResult, String> {
        let targets = self
            .project_needs_human_targets(store, project_id, requested)
            .await?;
        // An empty list would mean "every pending tab" to confirm_needs_human.
        if targets.is_empty() {
            return Ok(BrowserNeedsHumanConfirmResult {
                still_required: Vec::new(),
                cleared: Vec::new(),
            });
        }
        self.confirm_needs_human(&targets).await
    }

    pub(crate) async fn focus_needs_human_for_project(
        &self,
        store: &Store,
        project_id: Option<&str>,
        session: &str,
        tab_id: i64,
    ) -> Result<(), String> {
        let requested = [BrowserNeedsHumanTab {
            session: session.to_string(),
            tab_id,
            ..Default::default()
        }];
        if self
            .project_needs_human_targets(store, project_id, &requested)
            .await?
            .is_empty()
        {
            return Err(format!(
                "browser tab {tab_id} is not waiting for verification in this project"
            ));
        }
        self.focus_needs_human_tab(session, tab_id).await
    }

    pub(crate) async fn confirm_needs_human(
        &self,
        tabs: &[BrowserNeedsHumanTab],
    ) -> Result<BrowserNeedsHumanConfirmResult, String> {
        let targets = if tabs.is_empty() {
            self.snapshot_needs_human().await
        } else {
            tabs.to_vec()
        };
        let mut still_required = Vec::new();
        let mut cleared = Vec::new();
        for tab in targets {
            match self
                .execute_on(
                    Some(&tab.session),
                    Some(tab.tab_id),
                    TEXT_SCAN_SCRIPT,
                    Duration::from_millis(DEFAULT_TIMEOUT_MS),
                )
                .await
            {
                Ok(execution) => {
                    self.apply_human_verification(
                        &execution.session,
                        execution.tab_id,
                        &execution.value,
                        &tab.frame_id,
                        &tab.turn_id,
                    )
                    .await;
                    if human_verification_handoff(&execution.value).is_some() {
                        still_required.push(
                            self.needs_human
                                .lock()
                                .await
                                .get(&(execution.session.clone(), execution.tab_id))
                                .cloned()
                                .unwrap_or(tab),
                        );
                    } else {
                        cleared.push(tab);
                    }
                }
                Err(error)
                    if error.contains("is not available")
                        || error.contains("no HTTP(S) tabs")
                        || error.contains("no browser tab is selected") =>
                {
                    self.needs_human
                        .lock()
                        .await
                        .remove(&(tab.session.clone(), tab.tab_id));
                    self.persist_needs_human().await;
                    self.emit_needs_human().await;
                    cleared.push(tab);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(BrowserNeedsHumanConfirmResult {
            still_required,
            cleared,
        })
    }

    pub(crate) async fn focus_needs_human_tab(
        &self,
        session: &str,
        tab_id: i64,
    ) -> Result<(), String> {
        let code = json!({ "cmd": "tabs", "method": "switch", "tabId": tab_id }).to_string();
        self.send_command_on(
            Some(session),
            code,
            Duration::from_millis(DEFAULT_TIMEOUT_MS),
        )
        .await
        .map(|_| ())
    }

    async fn retry_pending_auto_close(&self) {
        let ids: Vec<String> = self
            .pending_cleanups
            .lock()
            .await
            .iter()
            .filter(|(_, row)| row.auto_close)
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            let Some(pending) = self.pending_cleanups.lock().await.remove(&id) else {
                continue;
            };
            if self.close_items(&pending.prompt.tabs).await.is_err() {
                self.pending_cleanups.lock().await.insert(id, pending);
            }
        }
        self.persist_pending().await;
    }

    /// Open the first available browser on its extension-manager page.
    /// Tests never spawn a browser (`can_launch` is false on `new()`).
    pub fn open_extension_setup(&self) -> BrowserExtensionSetup {
        let extension_path = self.verified_extension_path();
        let opened = self.can_launch
            && browser_extension_page_plan().is_some_and(|(program, args)| {
                spawn_browser_with_url(&program, &args)
                    .map_err(|error| {
                        tracing::warn!(target: "wisp", "extension page launch failed: {error}");
                    })
                    .is_ok()
            });
        BrowserExtensionSetup {
            extension_path,
            opened,
        }
    }

    pub async fn extension_status(&self) -> BrowserExtensionStatus {
        let bundled_version = bundled_manifest_version(&self.bundled_extension_dir);
        let integrity_verified = self.extension_integrity_verified();
        let extension_path = integrity_verified
            .then(|| dunce::canonicalize(&self.extension_dir).ok())
            .flatten()
            .map(|dir| dir.display().to_string());
        let state = self.state.lock().await;
        let shared = state.sessions.get("shared");
        let connected = shared.and_then(|slot| slot.client.as_ref()).is_some();
        let meta = shared.map(|slot| &slot.meta);
        let update_required =
            meta.is_some_and(|meta| session_requires_update(meta, bundled_version.as_deref()));
        BrowserExtensionStatus {
            connected,
            current_version: meta
                .map(|meta| meta.extension_version.clone())
                .filter(|version| !version.is_empty()),
            bundled_version,
            current_protocol: meta.map(|meta| meta.protocol_version).unwrap_or_default(),
            required_protocol: REQUIRED_PROTOCOL,
            update_required,
            automatic_reload_available: connected
                && meta.is_some_and(|meta| {
                    meta.capabilities
                        .iter()
                        .any(|capability| capability == "runtime_reload")
                }),
            extension_path_verified: extension_path.is_some(),
            extension_path,
            integrity_verified,
            error: state.extension_update_error.clone(),
        }
    }

    pub async fn update_extension(&self) -> BrowserExtensionUpdateResult {
        let _update_guard = self.extension_update_lock.lock().await;
        let synced = extension_manager::sync(
            &self.bundled_extension_dir,
            &self.extension_dir,
            EXTENSION_ID,
        );
        if let Err(error) = synced {
            self.state.lock().await.extension_update_error = Some(error.clone());
            return BrowserExtensionUpdateResult {
                outcome: "error".into(),
                status: self.extension_status().await,
                opened: false,
                error: Some(error),
            };
        }
        self.state.lock().await.extension_update_error = None;

        let status = self.extension_status().await;
        if !status.update_required {
            return BrowserExtensionUpdateResult {
                outcome: "updated".into(),
                status,
                opened: false,
                error: None,
            };
        }

        if status.automatic_reload_available {
            let command = json!({ "cmd": "runtime", "method": "reload" }).to_string();
            if self
                .send_command_on(
                    Some("shared"),
                    command,
                    Duration::from_millis(DEFAULT_TIMEOUT_MS),
                )
                .await
                .is_ok()
            {
                let deadline = tokio::time::Instant::now() + AUTO_LAUNCH_WAIT;
                while tokio::time::Instant::now() < deadline {
                    let refreshed = self.extension_status().await;
                    if refreshed.connected && !refreshed.update_required {
                        return BrowserExtensionUpdateResult {
                            outcome: "updated".into(),
                            status: refreshed,
                            opened: false,
                            error: None,
                        };
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            }
        }

        let setup = self.open_extension_setup();
        BrowserExtensionUpdateResult {
            outcome: "manual_reload_required".into(),
            status: self.extension_status().await,
            opened: setup.opened,
            error: None,
        }
    }

    /// Live connection status for the offline banner's recheck: the per-turn
    /// judgment is frozen into the transcript, so a banner from a transient
    /// disconnect sticks forever even after the extension reconnects (and
    /// resurrects on session reload). The UI rechecks through this before
    /// showing the banner.
    pub async fn extension_connected(&self) -> bool {
        self.client_connected().await
    }

    fn extension_integrity_verified(&self) -> bool {
        if self.managed_extension {
            extension_manager::verify(
                &self.bundled_extension_dir,
                &self.extension_dir,
                EXTENSION_ID,
            )
            .is_ok()
        } else {
            extension_manager::inspect(&self.extension_dir, EXTENSION_ID).is_ok()
        }
    }
}

/// Start the user's existing Chrome/Chromium/Edge so the unpacked Wisp
/// extension can reconnect. Does not use a temporary automation profile.
fn spawn_user_browser(url: Option<&str>) -> Result<(), String> {
    let (program, args) = first_available_browser()
        .ok_or_else(|| "no Chrome, Chromium, or Edge browser was found".to_string())?;
    let mut args = shared_browser_launch_args(&program, args);
    if let Some(url) = url {
        *args
            .last_mut()
            .expect("shared launch always includes a URL") = url.into();
    }
    let mut command = std::process::Command::new(&program);
    command
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x00000008 | 0x00000200);
    }
    command
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("failed to start {}: {error}", program.display()))
}

fn shared_browser_launch_args(program: &Path, mut args: Vec<String>) -> Vec<String> {
    if program.ends_with("open") {
        args.push("--args".into());
    }
    args.push(format!(
        "{}/",
        extensions_page_url(program, &args).replace("extensions", "newtab")
    ));
    args
}

fn first_available_browser() -> Option<(PathBuf, Vec<String>)> {
    browser_launch_candidates()
        .into_iter()
        .find(|(program, args)| launch_plan_available(program, args))
}

/// Launch plan for the first real browser executable, pointed at its
/// extension manager page. The `cmd /C start` fallback is skipped: it cannot
/// carry the `*://extensions` URL.
fn browser_extension_page_plan() -> Option<(PathBuf, Vec<String>)> {
    browser_launch_candidates()
        .into_iter()
        .filter(|(program, _)| program.file_name().and_then(|name| name.to_str()) != Some("cmd"))
        .find(|(program, args)| launch_plan_available(program, args))
        .map(|(program, args)| {
            let args = extension_page_launch_args(&program, args);
            (program, args)
        })
}

/// `open -a App` needs `--args` before `chrome://…`; Chromium executables take
/// the URL as a trailing argument.
fn extension_page_launch_args(program: &Path, mut args: Vec<String>) -> Vec<String> {
    let url = extensions_page_url(program, &args);
    if program.ends_with("open") {
        args.push("--args".into());
    }
    args.push(url.to_string());
    args
}

/// Each Chromium fork only understands its own `*://extensions` scheme.
fn extensions_page_url(program: &Path, args: &[String]) -> &'static str {
    let name = if program.ends_with("open") {
        // macOS `open -a "<App Name>"`: the browser identity sits in the args.
        args.get(1).map(String::as_str).unwrap_or_default()
    } else {
        program
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or_default()
    }
    .to_lowercase();
    if name.contains("edge") {
        "edge://extensions"
    } else if name.contains("brave") {
        "brave://extensions"
    } else {
        "chrome://extensions"
    }
}

/// Start `program` detached like `spawn_user_browser`, with caller-chosen args.
fn spawn_browser_with_url(program: &Path, args: &[String]) -> Result<(), String> {
    let mut command = std::process::Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x00000008 | 0x00000200);
    }
    command
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("failed to start {}: {error}", program.display()))
}

/// OS-specific launch plans. The first available program is used at runtime.
fn browser_launch_candidates() -> Vec<(PathBuf, Vec<String>)> {
    #[cfg(windows)]
    {
        let mut candidates = Vec::new();
        for root in [
            std::env::var_os("LOCALAPPDATA"),
            std::env::var_os("PROGRAMFILES"),
            std::env::var_os("PROGRAMFILES(X86)"),
        ]
        .into_iter()
        .flatten()
        {
            let root = PathBuf::from(root);
            candidates.push((
                root.join("Google/Chrome/Application/chrome.exe"),
                Vec::new(),
            ));
            candidates.push((
                root.join("Microsoft/Edge/Application/msedge.exe"),
                Vec::new(),
            ));
            candidates.push((
                root.join("BraveSoftware/Brave-Browser/Application/brave.exe"),
                Vec::new(),
            ));
        }
        candidates.push((
            PathBuf::from("cmd"),
            vec!["/C".into(), "start".into(), String::new(), "chrome".into()],
        ));
        candidates
    }
    #[cfg(target_os = "macos")]
    {
        [
            "Google Chrome",
            "Microsoft Edge",
            "Chromium",
            "Brave Browser",
        ]
        .into_iter()
        .map(|name| {
            (
                PathBuf::from("/usr/bin/open"),
                vec!["-a".into(), name.into()],
            )
        })
        .collect()
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        [
            "google-chrome-stable",
            "google-chrome",
            "chromium-browser",
            "chromium",
            "microsoft-edge-stable",
            "microsoft-edge",
            "brave-browser",
        ]
        .into_iter()
        .map(|name| (PathBuf::from(name), Vec::new()))
        .collect()
    }
}

fn launch_plan_available(
    program: &Path,
    #[cfg_attr(not(target_os = "macos"), allow(unused_variables))] args: &[String],
) -> bool {
    #[cfg(target_os = "macos")]
    {
        if program.ends_with("open") && args.first().map(String::as_str) == Some("-a") {
            return args.get(1).is_some_and(|name| {
                Path::new("/Applications")
                    .join(format!("{name}.app"))
                    .is_dir()
            });
        }
    }
    if program.components().count() > 1 {
        return program.is_file();
    }
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        let candidate = dir.join(program);
        candidate.is_file()
            || cfg!(windows) && dir.join(format!("{}.exe", program.display())).is_file()
    })
}

fn allowed_extension_origin(origin: Option<&str>) -> bool {
    origin == Some(EXTENSION_ORIGIN)
}

fn forbidden_response() -> ErrorResponse {
    tokio_tungstenite::tungstenite::http::Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Some(
            "Wisp browser bridge accepts Chrome extensions only".into(),
        ))
        .expect("static browser bridge rejection response")
}

fn fail_pending(state: &mut SessionState, reason: &str) {
    for (_, sender) in state.pending.drain() {
        let _ = sender.send(Err(reason.to_string()));
    }
}

fn replace_tabs(state: &mut SessionState, message: &Value) {
    let Some(tabs) = message.get("tabs").and_then(Value::as_array) else {
        return;
    };
    state.tabs = tabs
        .iter()
        .filter_map(parse_tab)
        .map(|tab| (tab.id, tab))
        .collect();
    // A stale selection must not survive; `select_tab` re-derives the default
    // inside the caller's scope.
    let live = &state.tabs;
    state
        .selected_by_frame
        .retain(|_, id| live.contains_key(id));
    if state.owners.len() > MAX_TRACKED_OWNERS {
        state.owners.retain(|id, _| live.contains_key(id));
    }
}

fn parse_tab(value: &Value) -> Option<BrowserTab> {
    let id = value.get("id").and_then(|id| {
        id.as_i64()
            .or_else(|| id.as_str().and_then(|id| id.parse().ok()))
    })?;
    Some(BrowserTab {
        id,
        url: value
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        title: value
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        active: value
            .get("active")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        window_id: value.get("windowId").and_then(Value::as_i64),
    })
}

fn parse_created_tab(value: &Value) -> Option<BrowserTab> {
    parse_tab(value.get("tab").unwrap_or(value))
}

fn json_command(script: &str) -> Option<Value> {
    serde_json::from_str(script.trim()).ok()
}

fn is_tabs_create(script: &str) -> bool {
    json_command(script).is_some_and(|value| {
        value.get("cmd").and_then(Value::as_str) == Some("tabs")
            && value.get("method").and_then(Value::as_str) == Some("create")
    })
}

fn close_ids_from_script(script: &str) -> Option<Vec<i64>> {
    let value = json_command(script)?;
    if value.get("cmd").and_then(Value::as_str) != Some("tabs") {
        return None;
    }
    if value.get("method").and_then(Value::as_str) != Some("close") {
        return None;
    }
    value
        .get("tabIds")
        .and_then(Value::as_array)
        .map(|rows| rows.iter().filter_map(Value::as_i64).collect::<Vec<_>>())
        .or_else(|| {
            value
                .get("tabId")
                .and_then(Value::as_i64)
                .map(|id| vec![id])
        })
        .filter(|ids| !ids.is_empty())
}

/// Pick the tab a command runs on. With a scope, an explicit tab must be
/// owned by the calling conversation and the default stays inside its tabs:
/// never the profile's active or first tab, which may be the user's or
/// another conversation's.
fn select_tab(
    state: &SessionState,
    requested: Option<i64>,
    scope: Option<&ToolScope>,
) -> Result<i64, String> {
    let Some(scope) = scope else {
        if state.tabs.is_empty() {
            return Err("browser extension is connected, but no HTTP(S) tabs are available".into());
        }
        if let Some(tab_id) = requested {
            return state
                .tabs
                .contains_key(&tab_id)
                .then_some(tab_id)
                .ok_or_else(|| {
                    format!(
                        "browser tab {tab_id} is not available; call web_scan with tabs_only=true"
                    )
                });
        }
        return state
            .selected_by_frame
            .get(selection_key(None))
            .copied()
            .filter(|tab_id| state.tabs.contains_key(tab_id))
            .or_else(|| state.tabs.values().find(|tab| tab.active).map(|tab| tab.id))
            .or_else(|| state.tabs.keys().next().copied())
            .ok_or_else(|| "no browser tab is selected".into());
    };
    let in_scope = |tab_id: &i64| state.tabs.contains_key(tab_id) && scope.owns(state, *tab_id);
    if let Some(tab_id) = requested {
        if !state.tabs.contains_key(&tab_id) {
            return Err(format!(
                "browser tab {tab_id} is not available; call web_scan with tabs_only=true"
            ));
        }
        return in_scope(&tab_id)
            .then_some(tab_id)
            .ok_or_else(|| out_of_scope_message(tab_id));
    }
    state
        .selected_by_frame
        .get(&scope.frame_id)
        .copied()
        .filter(in_scope)
        .or_else(|| state.tabs.keys().copied().find(in_scope))
        .ok_or_else(empty_scope_message)
}

fn selection_key(scope: Option<&ToolScope>) -> &str {
    scope.map_or("", |scope| scope.frame_id.as_str())
}

fn empty_scope_message() -> String {
    "This conversation has no browser tab yet. Tabs are isolated per conversation, so the user's tabs and other conversations' tabs are not available by default. Open one with web_open_tab (the shared profile keeps its sign-ins), or pass switch_tab_id=\"active\" (or a tab id) to ask the user for access to an existing tab.".into()
}

fn out_of_scope_message(tab_id: i64) -> String {
    format!(
        "browser tab {tab_id} is not shared with this conversation. Pass it as switch_tab_id to ask the user for access, or open your own tab with web_open_tab."
    )
}

fn grant_prompt(tab: &BrowserTab, owner: Option<&TabOwner>, scope: &ToolScope) -> String {
    let title = if tab.title.trim().is_empty() {
        "(untitled)"
    } else {
        tab.title.trim()
    };
    let mut prompt = format!(
        "Allow this conversation to control browser tab #{}: {title} ({})?",
        tab.id, tab.url
    );
    match owner {
        Some(owner) if owner.project_id != scope.project_id => prompt.push_str(
            " Another project's conversation opened it; approving moves control of the tab to this conversation.",
        ),
        Some(_) => prompt.push_str(
            " Another conversation in this project controls it; approving moves control of the tab to this conversation.",
        ),
        None => {}
    }
    prompt
}

fn wants_active_tab(args: &Value) -> bool {
    args.get("switch_tab_id")
        .and_then(Value::as_str)
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("active"))
}

/// JavaScript truthiness of a JSON value, as the extension's `||` sees it.
fn js_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0 && !n.is_nan()),
        Value::String(text) => !text.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// A JSON number JavaScript's `Number.isInteger` accepts (so `5.0` too).
fn js_integer(value: &Value) -> Option<i64> {
    value.as_i64().or_else(|| {
        value
            .as_f64()
            .filter(|n| n.is_finite() && n.fract() == 0.0 && n.abs() < 9.0e15)
            .map(|n| n as i64)
    })
}

/// Tab ids a JSON command would act on besides the request's own tab, read
/// the way `background.js` reads them. Errors for commands that must not run
/// under tab isolation at all.
fn scoped_tab_refs(script: &str) -> Result<Vec<i64>, String> {
    let trimmed = script.trim();
    let Ok(command) = serde_json::from_str::<Value>(trimmed) else {
        // JSON.parse accepts some inputs serde_json rejects (lone surrogate
        // escapes, huge numbers). Something shaped like a JSON object that
        // only the extension might parse as a command is refused rather than
        // waved through as page JavaScript.
        if trimmed.starts_with('{') && trimmed.ends_with('}') {
            return Err("this script looks like a JSON browser command but is not valid JSON; send a valid JSON command or plain JavaScript".into());
        }
        return Ok(Vec::new());
    };
    let Some(cmd) = command.get("cmd").filter(|cmd| js_truthy(cmd)) else {
        return Ok(Vec::new());
    };
    let explicit_id = |key: &str| -> Result<Option<i64>, String> {
        match command.get(key) {
            Some(value) if js_truthy(value) => js_integer(value)
                .map(Some)
                .ok_or_else(|| format!("{key} must be an integer tab id")),
            _ => Ok(None),
        }
    };
    match cmd.as_str() {
        Some("cdp") => {
            let method = command.get("method").and_then(Value::as_str).unwrap_or("");
            if method.starts_with("Target.") || method.starts_with("Browser.") {
                return Err(format!(
                    "CDP {method} can reach other tabs or windows, so it is not allowed while browser tabs are isolated per conversation. Use web_open_tab, or Page/Input/Runtime methods on your own tab."
                ));
            }
            Ok(explicit_id("tabId")?.into_iter().collect())
        }
        Some("tabs") => match command.get("method").and_then(Value::as_str) {
            Some("close") => match command.get("tabIds") {
                Some(Value::Array(rows)) => Ok(rows.iter().filter_map(js_integer).collect()),
                Some(value) if js_truthy(value) => Err("tabIds must be an array of tab ids".into()),
                _ => Ok(explicit_id("tabId")?.into_iter().collect()),
            },
            Some("switch") => Ok(explicit_id("tabId")?.into_iter().collect()),
            _ => Ok(Vec::new()),
        },
        _ => Ok(Vec::new()),
    }
}

/// Keep only rows of a tab list (`tabs` query result, close `remaining`) that
/// this conversation owns.
fn retain_owned_rows(rows: &mut Value, owned: &HashSet<i64>) {
    if let Some(rows) = rows.as_array_mut() {
        rows.retain(|row| parse_tab(row).is_some_and(|tab| owned.contains(&tab.id)));
    }
}

fn request_payload(id: &str, tab_id: Option<i64>, code: &str, timeout: Duration) -> String {
    let mut payload = json!({
        "id": id,
        "code": code,
        "timeoutMs": timeout.as_millis() as u64,
    });
    if let Some(tab_id) = tab_id {
        payload["tabId"] = json!(tab_id);
    }
    payload.to_string()
}

fn parse_bridge_reply(message: &Value) -> BridgeReply {
    BridgeReply {
        value: message
            .get("result")
            .or_else(|| message.get("data"))
            .cloned()
            .unwrap_or(Value::Null),
        ready: message.get("ready").and_then(Value::as_bool),
        wait: message
            .get("wait")
            .cloned()
            .filter(|value| !value.is_null()),
        new_tabs: message
            .get("newTabs")
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| {
                        Some(NewTab {
                            id: parse_tab(row)?.id,
                            opener: row.get("openerTabId").and_then(Value::as_i64),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn merge_ready_wait(mut payload: Value, ready: Option<bool>, wait: Option<Value>) -> Value {
    if let Some(ready) = ready {
        payload["ready"] = json!(ready);
    }
    if let Some(wait) = wait {
        payload["wait"] = wait;
    }
    payload
}

#[allow(dead_code)]
fn render_bridge_error(error: Option<&Value>) -> String {
    match error {
        Some(Value::String(error)) => error.clone(),
        Some(error) => serde_json::to_string_pretty(error).unwrap_or_else(|_| error.to_string()),
        None => "browser extension returned an unknown error".into(),
    }
}

fn session_arg(args: &Value) -> Result<Option<String>, String> {
    let Some(value) = args.get("session") else {
        return Ok(None);
    };
    let Some(name) = value.as_str() else {
        return Err(errors::structured(
            errors::SESSION_REQUIRED,
            "session must be a string",
            false,
        ));
    };
    if name != "shared" && name != "workspace" {
        return Err(errors::structured(
            errors::SESSION_REQUIRED,
            "session must be shared or workspace",
            false,
        ));
    }
    Ok(Some(name.to_string()))
}

fn tab_id_arg(args: &Value) -> Result<Option<i64>, String> {
    let Some(value) = args.get("switch_tab_id") else {
        return Ok(None);
    };
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        .map(Some)
        .ok_or_else(|| "switch_tab_id must be an integer tab id returned by web_scan".into())
}

fn open_tab_result(reply: BridgeReply, url: &str, filters: &BrowserUrlFilters) -> Value {
    let mut result = json!({ "tab": reply.value });
    if !filters.prefer.is_empty() {
        let preferred = filters.is_preferred(url);
        result["preferred"] = json!(preferred);
        if !preferred {
            result["prefer_hosts"] = json!(filters
                .prefer
                .iter()
                .map(|rule| rule.host.clone())
                .collect::<Vec<_>>());
        }
    }
    merge_ready_wait(result, reply.ready, reply.wait)
}

fn render_json(value: &Value) -> String {
    let rendered = serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string());
    if rendered.chars().count() <= MAX_RESULT_CHARS {
        return rendered;
    }
    let mut clipped: String = rendered.chars().take(MAX_RESULT_CHARS).collect();
    clipped.push_str("\n... browser result truncated");
    clipped
}

fn chat_tab(
    tabs: &[BrowserTab],
    requested: Option<i64>,
) -> Result<(i64, chat_site::ChatSite), String> {
    if tabs.is_empty() {
        return Err(format!(
            "no HTTP(S) tabs are available for web_agent_*. Open {} and sign in first.",
            chat_site::supported_sites_help()
        ));
    }
    let tab = if let Some(tab_id) = requested {
        tabs.iter().find(|tab| tab.id == tab_id).ok_or_else(|| {
            format!("browser tab {tab_id} is not available; call web_scan with tabs_only=true")
        })?
    } else {
        tabs.iter()
            .find(|tab| tab.active && chat_site::detect(&tab.url).is_some())
            .or_else(|| {
                tabs.iter()
                    .find(|tab| chat_site::detect(&tab.url).is_some())
            })
            .ok_or_else(|| {
                format!(
                    "web_agent_* needs an already-open signed-in tab at {}",
                    chat_site::supported_sites_help()
                )
            })?
    };
    let Some(site) = chat_site::detect(&tab.url) else {
        return Err(format!(
            "web_agent_* supports {} — this tab is not one of those chat sites",
            chat_site::supported_sites_help()
        ));
    };
    Ok((tab.id, site))
}

struct ChatTurn {
    session: Option<String>,
    tab_id: i64,
    site: chat_site::ChatSite,
    scope: Option<ToolScope>,
}

async fn begin_chat_turn(
    bridge: &BrowserBridge,
    args: &Value,
    env: &dyn ToolEnv,
    session: Option<String>,
    scope: Option<ToolScope>,
) -> Result<ChatTurn, String> {
    bridge.require_chat_capability(session.as_deref()).await?;
    let requested = bridge
        .tool_tab(args, env, session.as_deref(), scope.as_ref())
        .await?;
    let tabs = bridge.tabs_in(session.as_deref(), scope.as_ref()).await?;
    let (tab_id, site) = chat_tab(&tabs, requested).map_err(|error| match &scope {
        Some(_) => format!(
            "{error}. Browser tabs are isolated per conversation, so only this conversation's tabs count: open the chat site with web_open_tab (the shared profile keeps its sign-in), or pass switch_tab_id (\"active\" or a tab id) to ask the user for access to an open chat tab."
        ),
        None => error,
    })?;
    Ok(ChatTurn {
        session,
        tab_id,
        site,
        scope,
    })
}

/// Resolve a user-supplied project-relative path. Rejects absolute paths and
/// any `..`/prefix component, so tool arguments cannot escape the project
/// root ("path traversal").
fn project_relative_path(root: &Path, rel: &str) -> Result<PathBuf, String> {
    use std::path::Component;
    let trimmed = rel.trim();
    if trimmed.is_empty() {
        return Err("path must be a non-empty project-relative path".into());
    }
    let path = Path::new(trimmed);
    let inside_root = !path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_) | Component::CurDir));
    if !inside_root {
        return Err(format!(
            "path must stay inside the project (no absolute paths or '..' segments): {trimmed}"
        ));
    }
    Ok(root.join(path))
}

fn human_verification_handoff(page: &Value) -> Option<Value> {
    let title = page.get("title").and_then(Value::as_str).unwrap_or("");
    let text = page.get("text").and_then(Value::as_str).unwrap_or("");
    let content = format!("{title}\n{text}").to_ascii_lowercase();
    if !content.contains("are you a robot")
        || !(content.contains("confirm you are a human") || content.contains("captcha challenge"))
    {
        return None;
    }
    Some(json!({
        "required": true,
        "reason": "captcha_challenge",
        "instruction": "A verification prompt has been shown in the Wisp app. Stop browser automation. Do not call ask_user and do not click, solve, or bypass the challenge. End your turn. The user will confirm in the app after completing the challenge in the visible browser tab.",
        "resume": "After the user confirms, a follow-up message arrives. Call web_scan on the same tab and continue only when the challenge is no longer detected."
    }))
}

fn needs_human_block_message() -> String {
    "This tab needs human verification. Do not automate the challenge. Wait for the user to complete it in the visible browser tab and confirm in the Wisp app.".into()
}

fn script_allowed_during_needs_human(script: &str) -> bool {
    let Some(value) = json_command(script) else {
        return false;
    };
    match value.get("cmd").and_then(Value::as_str) {
        Some("control") => true,
        Some("tabs") => matches!(
            value.get("method").and_then(Value::as_str),
            None | Some("switch") | Some("query") | Some("list")
        ),
        _ => false,
    }
}

const SCAN_SCRIPT: &str = r##"(() => {
  const visible = (el) => {
    const s = getComputedStyle(el), r = el.getBoundingClientRect();
    return s.display !== 'none' && s.visibility !== 'hidden' && Number(s.opacity) > 0 && r.width > 0 && r.height > 0;
  };
  const selector = (el) => {
    if (el.id) {
      const id = '#' + CSS.escape(el.id);
      if (document.querySelectorAll(id).length === 1) return id;
    }
    const parts = [];
    for (let node = el; node && node.nodeType === 1 && parts.length < 6; node = node.parentElement) {
      let part = node.tagName.toLowerCase();
      const siblings = node.parentElement ? [...node.parentElement.children].filter(x => x.tagName === node.tagName) : [];
      if (siblings.length > 1) part += `:nth-of-type(${siblings.indexOf(node) + 1})`;
      parts.unshift(part);
      const candidate = parts.join(' > ');
      if (document.querySelectorAll(candidate).length === 1) return candidate;
    }
    return parts.join(' > ');
  };
  const query = 'a,button,input,textarea,select,summary,[role],[contenteditable=true],h1,h2,h3,label';
  const elements = [...document.querySelectorAll(query)].filter(visible).slice(0, 400).map((el) => {
    const r = el.getBoundingClientRect(), type = el.getAttribute('type') || '';
    return {
      selector: selector(el), tag: el.tagName.toLowerCase(), role: el.getAttribute('role') || undefined,
      text: (el.innerText || el.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 500) || undefined,
      aria_label: el.getAttribute('aria-label') || undefined, href: el.href || undefined, type: type || undefined,
      value: type.toLowerCase() === 'password' ? undefined : (el.value || undefined), disabled: !!el.disabled,
      rect: [Math.round(r.x), Math.round(r.y), Math.round(r.width), Math.round(r.height)]
    };
  });
  return { url: location.href, title: document.title, viewport: [innerWidth, innerHeight],
    ready_state: document.readyState,
    text: (document.body?.innerText || '').slice(0, 30000), elements };
})()"##;

const TEXT_SCAN_SCRIPT: &str = r#"(() => ({
  url: location.href,
  title: document.title,
  ready_state: document.readyState,
  text: (document.body?.innerText || '').slice(0, 50000)
}))()"#;

/// Acquire occupancy for this browser session and project+turn, or skip when
/// the host has no project/turn (CLI and tests). Does not release on Drop —
/// `complete_turn` owns the lifetime so two tools in one turn cannot open a
/// gap. Independent sessions use independent leases.
///
/// Also returns the caller's tab scope, derived only from the trusted env:
/// `None` without a project and frame (CLI and older tests), which means no
/// tab isolation, just as occupancy is skipped there.
fn occupy_or_fail(
    bridge: &BrowserBridge,
    env: &dyn ToolEnv,
    requested_session: Option<&str>,
) -> Result<Option<ToolScope>, ToolResult> {
    let Some(project_id) = env.project_id().filter(|id| !id.is_empty()) else {
        return Ok(None);
    };
    let session = resolve_session_name(requested_session).map_err(ToolResult::fail)?;
    if let Some(turn_id) = env.turn_id().filter(|id| !id.is_empty()) {
        bridge
            .occupy_turn(&session, project_id, turn_id)
            .map_err(ToolResult::fail)?;
    }
    Ok(env
        .frame_id()
        .filter(|id| !id.is_empty())
        .map(|frame_id| ToolScope {
            lane: session,
            project_id: project_id.to_string(),
            frame_id: frame_id.to_string(),
        }))
}

pub struct BrowserSetupTool {
    bridge: Arc<BrowserBridge>,
    store: Store,
}

impl BrowserSetupTool {
    pub fn new(bridge: Arc<BrowserBridge>, store: Store) -> Self {
        Self { bridge, store }
    }
}

#[async_trait]
impl Tool for BrowserSetupTool {
    fn name(&self) -> &str {
        "browser_setup"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(
            self.name(),
            "Call with no action before live page retrieval. The default is the user's shared daily Chrome profile: Wisp reuses it when connected and, when automatic launch is enabled, starts that normal profile so its installed extension can reconnect. Workspace is never a fallback; call action=start_workspace only when the user explicitly requests an isolated browser. Wisp verifies the bundled extension and maintains extension_path in a stable application-data directory. Copy extension_path character-for-character and never convert it between Windows, WSL, macOS, or Linux. If status is not connected, live_retrieval is false: do not answer live, latest, current, or URL-specific questions from prior knowledge; relay the steps and wait. If refused_connection is present, relay its explanation. If update_required is true, call this tool again with action=update_extension; compatible extensions reload automatically, while older extensions return manual_reload_required with the exact path. If extension_path_verified is false, report the validation error and never invent a path.",
            json!({
                "type": "object",
                "properties": {
                    "action": { "type": "string", "description": "Usually omit this for shared Chrome status/auto-launch. update_extension verifies the managed shared extension and attempts automatic reload. start_workspace and stop_workspace start or stop only the current project's isolated workspace browser. Each project has its own profile; up to three workspaces can run at once." },
                    "url": { "type": "string", "description": "Optional target http(s) URL for automatically launching disconnected shared Chrome; otherwise opens the new-tab page. Connected Chrome is left untouched." }
                },
                "additionalProperties": false
            }),
        )
    }

    fn preview(&self, _args: &Value) -> String {
        "show real-browser setup status and extension path".into()
    }

    async fn run(&self, args: &Value, env: &dyn ToolEnv) -> ToolResult {
        let action = args
            .get("action")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|action| !action.is_empty());
        if !matches!(action, Some("start_workspace" | "stop_workspace")) {
            if let Err(fail) = occupy_or_fail(&self.bridge, env, Some("shared")) {
                return fail;
            }
        }
        if let Some(action) = action {
            let result = match action {
                "update_extension" => {
                    let result = self.bridge.update_extension().await;
                    return match serde_json::to_value(result) {
                        Ok(value) => ToolResult::ok(render_json(&value)),
                        Err(error) => ToolResult::fail(format!(
                            "serialize browser extension update result: {error}"
                        )),
                    };
                }
                "start_workspace" => {
                    let result = self.bridge.start_workspace(env.project_id()).await;
                    if let Ok(info) = &result {
                        if let Err(fail) = occupy_or_fail(&self.bridge, env, info["lane"].as_str())
                        {
                            return fail;
                        }
                    }
                    result
                }
                "stop_workspace" => match project_workspace::require_project(env.project_id()) {
                    Ok(project_id) => Ok(self.bridge.stop_project_workspace(project_id).await),
                    Err(error) => Err(error),
                },
                _ => Err(
                    "action must be update_extension, start_workspace, or stop_workspace".into(),
                ),
            };
            return match result {
                Ok(value) => ToolResult::ok(render_json(&value)),
                Err(error) => ToolResult::fail(error),
            };
        }
        let filters = browser_url_filters::load(&self.store).await;
        let url = args
            .get("url")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|url| !url.is_empty());
        if let Some(url) = url {
            if !matches!(url::Url::parse(url), Ok(parsed) if matches!(parsed.scheme(), "http" | "https") && parsed.host_str().is_some())
            {
                return ToolResult::fail("url must be an absolute http:// or https:// address");
            }
            if let Some(rule) = filters.blocked(url) {
                return ToolResult::fail(browser_url_filters::block_message(url, rule));
            }
        }
        self.bridge
            .ensure_extension_with(None, || spawn_user_browser(url), AUTO_LAUNCH_WAIT)
            .await;
        let mut info = self.bridge.setup_info().await;
        info["workspace"] = self.bridge.workspace_status(env.project_id()).await;
        info["url_filters"] = json!({
            "block": filters.block,
            "prefer": filters.prefer,
            "matching": "host and subdomains; block is enforced; prefer is advisory for literature and similar tasks"
        });
        ToolResult::ok(render_json(&info))
    }
}

pub struct WebScanTool {
    bridge: Arc<BrowserBridge>,
}

impl WebScanTool {
    pub fn new(bridge: Arc<BrowserBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for WebScanTool {
    fn name(&self) -> &str {
        "web_scan"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(
            self.name(),
            "Read visible content and actionable elements from the user's real, persistent Chrome/Chromium session. The browser keeps its existing cookies, login state, extensions, GPU/WebGL behavior, and normal profile fingerprint. Waits until the tab's document is complete before reading (or until timeout). The result includes ready and page.ready_state; if ready is false, scan again instead of clicking a partial page. Use tabs_only first when the target tab is unclear. Tabs are isolated per conversation: you see and drive only tabs you opened (or popups they opened) and tabs the user shared with you. To use a tab the user already has open, pass switch_tab_id=\"active\" (or its id); the user is asked to approve. If the result contains human_intervention.required=true, a verification prompt has been shown to the user: stop browser automation, do not call ask_user, do not click the challenge, and end your turn.",
            json!({
                "type": "object",
                "properties": {
                    "tabs_only": { "type": "boolean", "description": "List this conversation's HTTP(S) tabs without reading page content" },
                    "switch_tab_id": { "type": ["integer", "string"], "description": "Tab id returned by this tool, or \"active\" for the tab the user is looking at; selects that tab for this and later calls. A tab not yet shared with this conversation needs the user's approval." },
                    "text_only": { "type": "boolean", "description": "Return page text without the actionable-element snapshot" },
                    "mode": { "type": "string", "description": "default | text | article. article adds images[], figures[], code_blocks[]" },
                    "session": { "type": "string", "description": "shared (default) or workspace (only when the user explicitly requested isolation)" }
                }
            }),
        )
    }

    fn minimum_approval(&self) -> Approval {
        Approval::Ask
    }

    fn preview(&self, args: &Value) -> String {
        if args
            .get("tabs_only")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            "list real-browser tabs".into()
        } else {
            args.get("switch_tab_id")
                .map(|tab| format!("scan real-browser tab {tab}"))
                .unwrap_or_else(|| "scan selected real-browser tab".into())
        }
    }

    async fn run(&self, args: &Value, env: &dyn ToolEnv) -> ToolResult {
        let session = match self.bridge.tool_session(args, env).await {
            Ok(session) => session,
            Err(error) => return ToolResult::fail(error),
        };
        let scope = match occupy_or_fail(&self.bridge, env, session.as_deref()) {
            Ok(scope) => scope,
            Err(fail) => return fail,
        };
        if args
            .get("tabs_only")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return match self
                .bridge
                .tabs_in(session.as_deref(), scope.as_ref())
                .await
            {
                Ok(tabs) if scope.is_some() => ToolResult::ok(render_json(&json!({
                    "tabs": tabs,
                    "tab_isolation": TAB_ISOLATION_NOTE
                }))),
                Ok(tabs) => ToolResult::ok(render_json(&json!({ "tabs": tabs }))),
                Err(error) => ToolResult::fail(error),
            };
        }
        let tab_id = match self
            .bridge
            .tool_tab(args, env, session.as_deref(), scope.as_ref())
            .await
        {
            Ok(tab_id) => tab_id,
            Err(error) => return ToolResult::fail(error),
        };
        let text_only = args
            .get("text_only")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let mode = args
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or(if text_only { "text" } else { "default" });
        if mode == "article" {
            if let Err(error) = self
                .bridge
                .require_capability(session.as_deref(), "article_scan")
                .await
            {
                return ToolResult::fail(error);
            }
        }
        let script = if mode == "article" {
            json!({ "cmd": "scan", "mode": "article" }).to_string()
        } else if mode == "text" || text_only {
            TEXT_SCAN_SCRIPT.to_string()
        } else {
            SCAN_SCRIPT.to_string()
        };
        match self
            .bridge
            .execute_in(
                session.as_deref(),
                tab_id,
                &script,
                Duration::from_millis(DEFAULT_TIMEOUT_MS),
                scope.as_ref(),
            )
            .await
        {
            Ok(execution) => {
                self.bridge
                    .apply_human_verification(
                        &execution.session,
                        execution.tab_id,
                        &execution.value,
                        env.frame_id().unwrap_or(""),
                        env.turn_id().unwrap_or(""),
                    )
                    .await;
                let handoff = human_verification_handoff(&execution.value);
                ToolResult::ok(render_json(&merge_ready_wait(
                    json!({
                        "human_intervention": handoff,
                        "tab_id": execution.tab_id,
                        "page": execution.value
                    }),
                    execution.ready,
                    execution.wait,
                )))
            }
            Err(error) => ToolResult::fail(error),
        }
    }
}

pub struct WebExecuteJsTool {
    bridge: Arc<BrowserBridge>,
    store: Store,
}

impl WebExecuteJsTool {
    pub fn new(bridge: Arc<BrowserBridge>, store: Store) -> Self {
        Self { bridge, store }
    }
}

#[async_trait]
impl Tool for WebExecuteJsTool {
    fn name(&self) -> &str {
        "web_execute_js"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(
            self.name(),
            "Execute JavaScript in a tab from the user's real, persistent Chrome/Chromium session. The extension waits until the tab's document is complete before running the script, and waits again if the script navigates. The result includes ready; if ready is false, scan again before clicking. Call web_scan first and do not guess selectors. To close tabs, never call window.close(); send {\"cmd\":\"tabs\",\"method\":\"close\",\"tabIds\":[...]} using ids returned by web_open_tab/web_scan. If web_scan reports human_intervention.required=true, do not automate the challenge; a verification prompt has been shown to the user. For a task that will trigger multiple file downloads, first tell the user how to allow automatic multiple downloads for the trusted target site at chrome://settings/content/automaticDownloads or edge://settings/content/automaticDownloads, then wait for confirmation; until confirmed, trigger at most one file download. A JSON script with cmd='cdp' may call one Chrome DevTools Protocol method for trusted input or other advanced browser actions. Tabs are isolated per conversation: tab commands and cdp tabId may only name this conversation's tabs, and Target.* / Browser.* CDP methods are refused.",
            json!({
                "type": "object",
                "properties": {
                    "script": { "type": "string", "description": "JavaScript, or a JSON command such as {\"cmd\":\"cdp\",\"method\":\"Input.dispatchMouseEvent\",\"params\":{...}}" },
                    "switch_tab_id": { "type": ["integer", "string"], "description": "Tab id returned by web_scan, or \"active\" for the tab the user is looking at. A tab not yet shared with this conversation needs the user's approval." },
                    "timeout_ms": { "type": "integer", "minimum": 1, "maximum": 60000, "description": "Execution timeout in milliseconds (default 15000)" },
                    "session": { "type": "string", "description": "shared (default) or workspace (only when the user explicitly requested isolation)" }
                },
                "required": ["script"]
            }),
        )
    }

    fn minimum_approval(&self) -> Approval {
        Approval::Ask
    }

    fn preview(&self, args: &Value) -> String {
        let script = args.get("script").and_then(Value::as_str).unwrap_or("");
        let mut preview: String = script.chars().take(240).collect();
        if script.chars().count() > 240 {
            preview.push('…');
        }
        preview
    }

    async fn run(&self, args: &Value, env: &dyn ToolEnv) -> ToolResult {
        let session = match self.bridge.tool_session(args, env).await {
            Ok(session) => session,
            Err(error) => return ToolResult::fail(error),
        };
        let scope = match occupy_or_fail(&self.bridge, env, session.as_deref()) {
            Ok(scope) => scope,
            Err(fail) => return fail,
        };
        let Some(script) = args
            .get("script")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|script| !script.is_empty())
        else {
            return ToolResult::fail("missing required argument 'script'");
        };
        if script.len() > MAX_SCRIPT_BYTES {
            return ToolResult::fail(format!(
                "browser script is {} bytes (maximum {MAX_SCRIPT_BYTES})",
                script.len()
            ));
        }
        if script.starts_with("window.close()") {
            return ToolResult::fail(
                "window.close() cannot close ordinary browser tabs. Use the browser-use skill's tab command: {\"cmd\":\"tabs\",\"method\":\"close\",\"tabIds\":[...]} with tab ids returned by web_open_tab/web_scan.",
            );
        }
        let filters = browser_url_filters::load(&self.store).await;
        if let Some((url, rule)) = filters.blocked_navigation(script) {
            return ToolResult::fail(browser_url_filters::block_message(&url, rule));
        }
        // Under tab isolation a JSON tabs.create goes through the same path
        // as web_open_tab: the project's fixed window, owned by this
        // conversation, and no existing tab needed to carry the command.
        if let Some(scope) = scope.as_ref().filter(|_| is_tabs_create(script)) {
            return self
                .create_scoped_tab(script, session.as_deref(), scope, env)
                .await;
        }
        let tab_id = match self
            .bridge
            .tool_tab(args, env, session.as_deref(), scope.as_ref())
            .await
        {
            Ok(tab_id) => tab_id,
            Err(error) => return ToolResult::fail(error),
        };
        if let Some(scope) = &scope {
            if let Err(error) = self.bridge.refuse_if_out_of_scope(scope, script).await {
                return ToolResult::fail(error);
            }
        }
        let timeout_ms = args
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_TIMEOUT_MS)
            .clamp(1, MAX_TIMEOUT_MS);
        if let Err(error) = self
            .bridge
            .refuse_if_needs_human(session.as_deref(), tab_id, script, scope.as_ref())
            .await
        {
            return ToolResult::fail(error);
        }
        match self
            .bridge
            .execute_in(
                session.as_deref(),
                tab_id,
                script,
                Duration::from_millis(timeout_ms),
                scope.as_ref(),
            )
            .await
        {
            Ok(mut execution) => {
                if is_tabs_create(script) {
                    if let Some(turn_id) = env.turn_id() {
                        self.bridge
                            .record_opened_tab(
                                turn_id,
                                env.frame_id().unwrap_or(""),
                                &execution.session,
                                &execution.value,
                                scope.as_ref(),
                            )
                            .await;
                    }
                }
                if let Some(ids) = close_ids_from_script(script) {
                    self.bridge.unrecord_tabs(&execution.session, &ids).await;
                }
                if let Some(scope) = &scope {
                    let tabs_method = json_command(script)
                        .filter(|command| {
                            command.get("cmd").and_then(Value::as_str) == Some("tabs")
                        })
                        .map(|command| {
                            command
                                .get("method")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string()
                        });
                    if let Some(method) = tabs_method {
                        let owned = self.bridge.owned_ids(scope).await;
                        match method.as_str() {
                            "close" => {
                                if let Some(rows) = execution.value.get_mut("remaining") {
                                    retain_owned_rows(rows, &owned);
                                }
                            }
                            "switch" => {}
                            _ => retain_owned_rows(&mut execution.value, &owned),
                        }
                    }
                }
                let mut result = json!({
                    "tab_id": execution.tab_id,
                    "result": execution.value
                });
                if !execution.adopted_tabs.is_empty() {
                    result["new_tabs"] = json!(execution.adopted_tabs);
                }
                ToolResult::ok(render_json(&merge_ready_wait(
                    result,
                    execution.ready,
                    execution.wait,
                )))
            }
            Err(error) => ToolResult::fail(error),
        }
    }
}

impl WebExecuteJsTool {
    async fn create_scoped_tab(
        &self,
        script: &str,
        session: Option<&str>,
        scope: &ToolScope,
        env: &dyn ToolEnv,
    ) -> ToolResult {
        let command = json_command(script).unwrap_or_default();
        let Some(url) = command
            .get("url")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|url| !url.is_empty())
        else {
            return ToolResult::fail("tabs.create needs a url; or use web_open_tab");
        };
        let active = command
            .get("active")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        match self
            .bridge
            .open_tab_on(session, url, active, Some(scope))
            .await
        {
            Ok((session_name, reply, note)) => {
                if let Some(turn_id) = env.turn_id() {
                    self.bridge
                        .record_opened_tab(
                            turn_id,
                            env.frame_id().unwrap_or(""),
                            &session_name,
                            &reply.value,
                            Some(scope),
                        )
                        .await;
                }
                let mut result = json!({
                    "tab_id": parse_created_tab(&reply.value).map(|tab| tab.id),
                    "result": reply.value
                });
                if let Some(note) = note {
                    result["window_note"] = json!(note);
                }
                ToolResult::ok(render_json(&merge_ready_wait(
                    result,
                    reply.ready,
                    reply.wait,
                )))
            }
            Err(error) => ToolResult::fail(error),
        }
    }
}

pub struct WebOpenTabTool {
    bridge: Arc<BrowserBridge>,
    store: Store,
}

impl WebOpenTabTool {
    pub fn new(bridge: Arc<BrowserBridge>, store: Store) -> Self {
        Self { bridge, store }
    }
}

#[async_trait]
impl Tool for WebOpenTabTool {
    fn name(&self) -> &str {
        "web_open_tab"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(
            self.name(),
            "Open a new tab at an http(s) URL in the user's real, persistent Chrome/Chromium session. Works even when no tab is open yet, so use this to start browsing. Waits until the new tab's document is complete (or until timeout). The result includes the new tab id plus ready; if ready is false, call web_scan before acting. Pass the tab id as switch_tab_id to web_scan or web_execute_js. The tab belongs to this conversation and opens in this project's own browser window, not the window the user is using; window_note explains when that fixed window was rebuilt or is unavailable. User-defined blocked hosts from Settings → Browser are refused before the tab opens. When url_filters.prefer is non-empty, prefer those hosts for literature and similar retrieval.",
            json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "Absolute http:// or https:// URL to open" },
                    "active": { "type": "boolean", "description": "Focus the new tab (default false)" },
                    "session": { "type": "string", "description": "shared (default) or workspace (only when the user explicitly requested isolation)" }
                },
                "required": ["url"]
            }),
        )
    }

    fn minimum_approval(&self) -> Approval {
        Approval::Ask
    }

    fn preview(&self, args: &Value) -> String {
        let url = args.get("url").and_then(Value::as_str).unwrap_or("");
        format!("open real-browser tab at {url}")
    }

    async fn run(&self, args: &Value, env: &dyn ToolEnv) -> ToolResult {
        let session = match self.bridge.tool_session(args, env).await {
            Ok(session) => session,
            Err(error) => return ToolResult::fail(error),
        };
        let scope = match occupy_or_fail(&self.bridge, env, session.as_deref()) {
            Ok(scope) => scope,
            Err(fail) => return fail,
        };
        let Some(url) = args
            .get("url")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|url| !url.is_empty())
        else {
            return ToolResult::fail("missing required argument 'url'");
        };
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            return ToolResult::fail("url must be an absolute http:// or https:// address");
        }
        let filters = browser_url_filters::load(&self.store).await;
        if let Some(rule) = filters.blocked(url) {
            return ToolResult::fail(browser_url_filters::block_message(url, rule));
        }
        let active = args.get("active").and_then(Value::as_bool).unwrap_or(false);
        match self
            .bridge
            .open_tab_on(session.as_deref(), url, active, scope.as_ref())
            .await
        {
            Ok((session_name, reply, note)) => {
                if let Some(turn_id) = env.turn_id() {
                    self.bridge
                        .record_opened_tab(
                            turn_id,
                            env.frame_id().unwrap_or(""),
                            &session_name,
                            &reply.value,
                            scope.as_ref(),
                        )
                        .await;
                }
                let mut result = open_tab_result(reply, url, &filters);
                if let Some(note) = note {
                    result["window_note"] = json!(note);
                }
                ToolResult::ok(render_json(&result))
            }
            Err(error) => ToolResult::fail(error),
        }
    }
}

pub struct WebScreenshotTool {
    bridge: Arc<BrowserBridge>,
}

impl WebScreenshotTool {
    pub fn new(bridge: Arc<BrowserBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for WebScreenshotTool {
    fn name(&self) -> &str {
        "web_screenshot"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(
            self.name(),
            "Look at what a tab in the user's real Chrome/Chromium session is showing. Waits until the tab's document is complete before capturing. Use it when web_scan's text and element snapshot is not enough: rendered layout, a chart or diagram, a canvas/WebGL page, a QR code, a PDF or image viewer, or a page that looks wrong and needs eyes. Captures the visible viewport of the tab; to reach content below the fold, scroll with web_execute_js first and capture again. Pass 'question' to say what should be read out of the screenshot.",
            json!({
                "type": "object",
                "properties": {
                    "switch_tab_id": { "type": ["integer", "string"], "description": "Tab id returned by web_scan; selects that tab for this and later calls" },
                    "question": { "type": "string", "description": "What to look for in the screenshot, e.g. 'is the login QR code visible and not expired?'" },
                    "full_page": { "type": "boolean" },
                    "selector": { "type": "string" },
                    "save_path": { "type": "string", "description": "Optional project-relative PNG path. Screenshots are not original figures." },
                    "session": { "type": "string", "description": "shared (default) or workspace (only when the user explicitly requested isolation)" }
                }
            }),
        )
    }

    fn minimum_approval(&self) -> Approval {
        Approval::Ask
    }

    fn preview(&self, args: &Value) -> String {
        args.get("switch_tab_id")
            .map(|tab| format!("screenshot real-browser tab {tab}"))
            .unwrap_or_else(|| "screenshot selected real-browser tab".into())
    }

    async fn run(&self, args: &Value, env: &dyn ToolEnv) -> ToolResult {
        let session = match self.bridge.tool_session(args, env).await {
            Ok(session) => session,
            Err(error) => return ToolResult::fail(error),
        };
        let scope = match occupy_or_fail(&self.bridge, env, session.as_deref()) {
            Ok(scope) => scope,
            Err(fail) => return fail,
        };
        let tab_id = match self
            .bridge
            .tool_tab(args, env, session.as_deref(), scope.as_ref())
            .await
        {
            Ok(tab_id) => tab_id,
            Err(error) => return ToolResult::fail(error),
        };
        // Viewport JPEG stays on the vision path. full_page / selector / save_path
        // write a PNG to the project and must not be treated as an original figure.
        let full_page = args
            .get("full_page")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let selector = args.get("selector").and_then(Value::as_str);
        let save_path = args.get("save_path").and_then(Value::as_str);
        let persist_png = full_page || selector.is_some() || save_path.is_some();
        if persist_png {
            let capability = if selector.is_some() {
                "selector_screenshot"
            } else {
                "full_page_screenshot"
            };
            if let Err(error) = self
                .bridge
                .require_capability(session.as_deref(), capability)
                .await
            {
                return ToolResult::fail(error);
            }
        }
        let code = if persist_png {
            json!({ "cmd": "capture", "full_page": full_page, "selector": selector, "format": "png" }).to_string()
        } else {
            json!({
                "cmd": "cdp",
                "method": "Page.captureScreenshot",
                "params": { "format": "jpeg", "quality": 80 }
            })
            .to_string()
        };
        let execution = match self
            .bridge
            .execute_in(
                session.as_deref(),
                tab_id,
                &code,
                Duration::from_millis(DEFAULT_TIMEOUT_MS),
                scope.as_ref(),
            )
            .await
        {
            Ok(execution) => execution,
            Err(error) => return ToolResult::fail(error),
        };
        let Some(data) = execution
            .value
            .get("data")
            .and_then(Value::as_str)
            .filter(|data| !data.is_empty())
        else {
            return ToolResult::fail("browser screenshot returned no image data");
        };
        if data.len() > MAX_SCREENSHOT_B64 {
            return ToolResult::fail(format!(
                "browser screenshot is too large ({} bytes of base64); reduce the browser window size and retry",
                data.len()
            ));
        }
        if persist_png {
            let bytes =
                match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, data) {
                    Ok(bytes) => bytes,
                    Err(error) => return ToolResult::fail(format!("decode screenshot: {error}")),
                };
            let target = match save_path.map(str::trim).filter(|rel| !rel.is_empty()) {
                Some(rel) => match project_relative_path(env.project_root(), rel) {
                    Ok(path) => path,
                    Err(error) => return ToolResult::fail(format!("save_path: {error}")),
                },
                _ => {
                    let dir = env
                        .project_root()
                        .join("browser-assets")
                        .join("screenshots");
                    if let Err(error) = std::fs::create_dir_all(&dir) {
                        return ToolResult::fail(format!("create screenshot dir: {error}"));
                    }
                    dir.join(format!("shot-{}.png", Uuid::new_v4()))
                }
            };
            if let Some(parent) = target.parent() {
                if let Err(error) = std::fs::create_dir_all(parent) {
                    return ToolResult::fail(format!("create screenshot parent: {error}"));
                }
            }
            if let Err(error) = std::fs::write(&target, &bytes) {
                return ToolResult::fail(format!("write screenshot: {error}"));
            }
            let sha = hex::encode(Sha256::digest(&bytes));
            return ToolResult::ok(render_json(&json!({
                "tab_id": execution.tab_id,
                "path": target.display().to_string(),
                "bytes": bytes.len(),
                "sha256": sha,
                "note": "screenshot PNG is not an original figure"
            })));
        }
        ToolResult::image(ImageData {
            mime: "image/jpeg".into(),
            data_url: format!("data:image/jpeg;base64,{data}"),
            label: format!(
                "Screenshot of real browser tab {} ({} KB)",
                execution.tab_id,
                data.len() / 1024
            ),
        })
    }
}

pub struct WebSaveAssetsTool {
    bridge: Arc<BrowserBridge>,
}

impl WebSaveAssetsTool {
    pub fn new(bridge: Arc<BrowserBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for WebSaveAssetsTool {
    fn name(&self) -> &str {
        "web_save_assets"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(
            self.name(),
            "Download page assets (images, PDFs, zips) through the connected Chrome session using the extension host permission. Files are staged under Downloads/WispBrowserStaging then copied into the project. Never uses page fetch/CORS. Pass session when both browsers are connected.",
            json!({
                "type": "object",
                "properties": {
                    "urls": { "type": "array", "items": { "type": "string" }, "description": "http(s) asset URLs" },
                    "referrer": { "type": "string" },
                    "dest_dir": { "type": "string", "description": "Project-relative destination, default browser-assets" },
                    "session": { "type": "string", "description": "shared (default) or workspace (only when the user explicitly requested isolation)" },
                    "switch_tab_id": { "type": ["integer", "string"] }
                },
                "required": ["urls"]
            }),
        )
    }

    fn minimum_approval(&self) -> Approval {
        Approval::Ask
    }

    fn preview(&self, args: &Value) -> String {
        let n = args
            .get("urls")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        format!("save {n} browser asset(s)")
    }

    async fn run(&self, args: &Value, env: &dyn ToolEnv) -> ToolResult {
        let session = match self.bridge.tool_session(args, env).await {
            Ok(session) => session,
            Err(error) => return ToolResult::fail(error),
        };
        let scope = match occupy_or_fail(&self.bridge, env, session.as_deref()) {
            Ok(scope) => scope,
            Err(fail) => return fail,
        };
        let Some(urls) = args.get("urls").and_then(Value::as_array) else {
            return ToolResult::fail("urls is required");
        };
        if urls.is_empty() {
            return ToolResult::fail("urls is empty");
        }
        if let Err(error) = self
            .bridge
            .require_capability(session.as_deref(), "asset_download")
            .await
        {
            return ToolResult::fail(error);
        }
        let dest_rel = args
            .get("dest_dir")
            .and_then(Value::as_str)
            .unwrap_or("browser-assets");
        let dest = match project_relative_path(env.project_root(), dest_rel) {
            Ok(dest) => dest,
            Err(error) => return ToolResult::fail(format!("dest_dir: {error}")),
        };
        if let Err(error) = std::fs::create_dir_all(&dest) {
            return ToolResult::fail(format!("create dest dir: {error}"));
        }
        let referrer = args.get("referrer").and_then(Value::as_str).unwrap_or("");
        let tab_id = match self
            .bridge
            .tool_tab(args, env, session.as_deref(), scope.as_ref())
            .await
        {
            Ok(tab_id) => tab_id,
            Err(error) => return ToolResult::fail(error),
        };
        let mut saved = Vec::new();
        for url_value in urls {
            let Some(url) = url_value.as_str() else {
                continue;
            };
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return ToolResult::fail(errors::structured(
                    errors::ASSET_BLOCKED,
                    "only http(s) asset URLs are allowed",
                    false,
                ));
            }
            let command =
                json!({ "cmd": "download", "url": url, "referrer": referrer }).to_string();
            match self
                .bridge
                .execute_in(
                    session.as_deref(),
                    tab_id,
                    &command,
                    Duration::from_millis(MAX_TIMEOUT_MS),
                    scope.as_ref(),
                )
                .await
            {
                Ok(execution) => {
                    let filename = execution
                        .value
                        .get("filename")
                        .and_then(Value::as_str)
                        .unwrap_or("WispBrowserStaging/download.bin");
                    let staged = execution
                        .value
                        .get("absolute_path")
                        .and_then(Value::as_str)
                        .filter(|path| !path.is_empty())
                        .map(PathBuf::from)
                        .unwrap_or_else(|| {
                            dirs::download_dir()
                                .unwrap_or_else(|| env.project_root().join("Downloads"))
                                .join(filename)
                        });
                    let name = staged
                        .file_name()
                        .or_else(|| Path::new(filename).file_name())
                        .unwrap_or_default();
                    let target = dest.join(name);
                    let mut copied = None;
                    for _ in 0..20 {
                        if staged.is_file() {
                            match std::fs::copy(&staged, &target) {
                                Ok(bytes) => copied = Some(bytes),
                                Err(error) => {
                                    return ToolResult::fail(format!("copy staged asset: {error}"))
                                }
                            }
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(250)).await;
                    }
                    let sha = if target.is_file() {
                        match std::fs::read(&target) {
                            Ok(bytes) => hex::encode(Sha256::digest(&bytes)),
                            Err(error) => {
                                return ToolResult::fail(format!("read copied asset: {error}"))
                            }
                        }
                    } else {
                        String::new()
                    };
                    saved.push(json!({
                        "source_url": url,
                        "path": target.display().to_string(),
                        "staged": staged.display().to_string(),
                        "copied_bytes": copied,
                        "sha256": sha,
                        "download": execution.value,
                        "ready": execution.ready
                    }));
                }
                Err(error) => return ToolResult::fail(error),
            }
        }
        ToolResult::ok(render_json(
            &json!({ "saved": saved, "dest_dir": dest.display().to_string() }),
        ))
    }
}

pub struct WebAgentSendTool {
    bridge: Arc<BrowserBridge>,
}

impl WebAgentSendTool {
    pub fn new(bridge: Arc<BrowserBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for WebAgentSendTool {
    fn name(&self) -> &str {
        "web_agent_send"
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), "Send one prompt to a signed-in in-browser chat composer (ChatGPT, Gemini, or Google AI Mode). Requires an already-open tab at chatgpt.com, gemini.google.com, or google.com/search?udm=50. Does not type passwords. Defaults to the shared daily browser; pass workspace only when the user explicitly requested isolation.", json!({
            "type": "object",
            "properties": {
                "prompt": { "type": "string" },
                "session": { "type": "string", "description": "shared (default) or workspace (only when the user explicitly requested isolation)" },
                "switch_tab_id": { "type": ["integer", "string"] }
            },
            "required": ["prompt"]
        }))
    }
    fn minimum_approval(&self) -> Approval {
        Approval::Ask
    }
    fn preview(&self, args: &Value) -> String {
        format!(
            "send in-browser chat prompt: {}",
            args.get("prompt")
                .and_then(Value::as_str)
                .unwrap_or("")
                .chars()
                .take(80)
                .collect::<String>()
        )
    }
    async fn run(&self, args: &Value, env: &dyn ToolEnv) -> ToolResult {
        let session = match self.bridge.tool_session(args, env).await {
            Ok(session) => session,
            Err(error) => return ToolResult::fail(error),
        };
        let scope = match occupy_or_fail(&self.bridge, env, session.as_deref()) {
            Ok(scope) => scope,
            Err(fail) => return fail,
        };
        let turn = match begin_chat_turn(&self.bridge, args, env, session, scope).await {
            Ok(turn) => turn,
            Err(error) => return ToolResult::fail(error),
        };
        let Some(prompt) = args
            .get("prompt")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        else {
            return ToolResult::fail("prompt is required");
        };
        let ready = match self
            .bridge
            .execute_in(
                turn.session.as_deref(),
                Some(turn.tab_id),
                &chat_site::ready_script(),
                Duration::from_millis(DEFAULT_TIMEOUT_MS),
                turn.scope.as_ref(),
            )
            .await
        {
            Ok(ready) => ready,
            Err(error) => return ToolResult::fail(error),
        };
        if let Some(blocked) = ready.value.get("blocked").and_then(Value::as_str) {
            return ToolResult::fail(format!(
                "{} page is blocked ({blocked}). Complete login or captcha in the visible tab, then retry.",
                turn.site.label()
            ));
        }
        let fill = match self
            .bridge
            .execute_in(
                turn.session.as_deref(),
                Some(turn.tab_id),
                &chat_site::send_script(prompt),
                Duration::from_millis(DEFAULT_TIMEOUT_MS),
                turn.scope.as_ref(),
            )
            .await
        {
            Ok(v) => v,
            Err(e) => return ToolResult::fail(e),
        };
        let sent = match self
            .bridge
            .execute_in(
                turn.session.as_deref(),
                Some(turn.tab_id),
                &chat_site::click_send_script(),
                Duration::from_millis(DEFAULT_TIMEOUT_MS),
                turn.scope.as_ref(),
            )
            .await
        {
            Ok(v) => v,
            Err(e) => return ToolResult::fail(e),
        };
        ToolResult::ok(render_json(&json!({
            "site": turn.site.as_str(),
            "prompt": prompt,
            "filled": fill.value,
            "sent": sent.value,
            "tab_id": sent.tab_id
        })))
    }
}

pub struct WebAgentWaitTool {
    bridge: Arc<BrowserBridge>,
}

impl WebAgentWaitTool {
    pub fn new(bridge: Arc<BrowserBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for WebAgentWaitTool {
    fn name(&self) -> &str {
        "web_agent_wait"
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), "Wait until the in-browser chat turn looks complete (stop control gone / assistant text stable). Works on ChatGPT, Gemini, and Google AI Mode. Uses the Wait Engine, not document.complete.", json!({
            "type": "object",
            "properties": {
                "session": { "type": "string", "description": "shared (default) or workspace (only when the user explicitly requested isolation)" },
                "switch_tab_id": { "type": ["integer", "string"] },
                "timeout_ms": { "type": "integer" }
            }
        }))
    }
    fn minimum_approval(&self) -> Approval {
        Approval::Ask
    }
    fn preview(&self, _args: &Value) -> String {
        "wait for in-browser chat reply".into()
    }
    async fn run(&self, args: &Value, env: &dyn ToolEnv) -> ToolResult {
        let session = match self.bridge.tool_session(args, env).await {
            Ok(session) => session,
            Err(error) => return ToolResult::fail(error),
        };
        let scope = match occupy_or_fail(&self.bridge, env, session.as_deref()) {
            Ok(scope) => scope,
            Err(fail) => return fail,
        };
        let turn = match begin_chat_turn(&self.bridge, args, env, session, scope).await {
            Ok(turn) => turn,
            Err(error) => return ToolResult::fail(error),
        };
        let timeout_ms = args
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(45_000)
            .clamp(1, MAX_TIMEOUT_MS);
        let started = std::time::Instant::now();
        let command = json!({
            "cmd": "wait",
            "spec": turn.site.wait_spec(),
            "timeoutMs": timeout_ms
        })
        .to_string();
        match self
            .bridge
            .execute_in(
                turn.session.as_deref(),
                Some(turn.tab_id),
                &command,
                Duration::from_millis(timeout_ms),
                turn.scope.as_ref(),
            )
            .await
        {
            Ok(v) => ToolResult::ok(render_json(&merge_ready_wait(
                json!({
                    "site": turn.site.as_str(),
                    "tab_id": v.tab_id,
                    "result": v.value,
                    "elapsed_ms": started.elapsed().as_millis() as u64,
                    "status": if v.ready.unwrap_or(false) { "complete" } else { "waiting" }
                }),
                v.ready,
                v.wait,
            ))),
            Err(e) => ToolResult::fail(e),
        }
    }
}

pub struct WebAgentReadTool {
    bridge: Arc<BrowserBridge>,
}

impl WebAgentReadTool {
    pub fn new(bridge: Arc<BrowserBridge>) -> Self {
        Self { bridge }
    }
}

#[async_trait]
impl Tool for WebAgentReadTool {
    fn name(&self) -> &str {
        "web_agent_read"
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema::new(
            self.name(),
            "Read the latest in-browser chat assistant turn (ChatGPT, Gemini, or Google AI Mode) as {answer_text, citations, status, site}.",
            json!({
                "type": "object",
                "properties": {
                    "session": { "type": "string", "description": "shared (default) or workspace (only when the user explicitly requested isolation)" },
                    "switch_tab_id": { "type": ["integer", "string"] }
                }
            }),
        )
    }
    fn minimum_approval(&self) -> Approval {
        Approval::Ask
    }
    fn preview(&self, _args: &Value) -> String {
        "read last in-browser chat answer".into()
    }
    async fn run(&self, args: &Value, env: &dyn ToolEnv) -> ToolResult {
        let session = match self.bridge.tool_session(args, env).await {
            Ok(session) => session,
            Err(error) => return ToolResult::fail(error),
        };
        let scope = match occupy_or_fail(&self.bridge, env, session.as_deref()) {
            Ok(scope) => scope,
            Err(fail) => return fail,
        };
        let turn = match begin_chat_turn(&self.bridge, args, env, session, scope).await {
            Ok(turn) => turn,
            Err(error) => return ToolResult::fail(error),
        };
        match self
            .bridge
            .execute_in(
                turn.session.as_deref(),
                Some(turn.tab_id),
                &chat_site::read_script(),
                Duration::from_millis(DEFAULT_TIMEOUT_MS),
                turn.scope.as_ref(),
            )
            .await
        {
            Ok(v) => {
                let mut parsed = chat_site::parse_read(&v.value);
                parsed["tab_id"] = json!(v.tab_id);
                parsed["site"] = json!(turn.site.as_str());
                parsed["prompt"] = Value::Null;
                parsed["elapsed_ms"] = json!(0);
                ToolResult::ok(render_json(&merge_ready_wait(parsed, v.ready, v.wait)))
            }
            Err(e) => ToolResult::fail(e),
        }
    }
}

#[tauri::command]
pub async fn list_pending_browser_tab_cleanups(
    state: tauri::State<'_, crate::AppState>,
    window: crate::workspace_surface::WorkspaceSurface,
) -> Result<Vec<BrowserTabCleanupPrompt>, String> {
    let project_id = crate::window_bound_project_id(&state, window.label());
    state
        .browser_bridge
        .project_pending_cleanups(&state.store, project_id.as_deref())
        .await
}

async fn browser_frame_belongs_to_project(
    store: &Store,
    frame_id: &str,
    project_id: Option<&str>,
) -> Result<bool, String> {
    let Some(project_id) = project_id else {
        return Ok(false);
    };
    Ok(store
        .frame_project_id(frame_id)
        .await
        .map_err(|e| e.to_string())?
        .as_deref()
        == Some(project_id))
}

pub(crate) async fn project_browser_needs_human(
    store: &Store,
    tabs: &[BrowserNeedsHumanTab],
    project_id: Option<&str>,
) -> Result<BrowserNeedsHumanPrompt, String> {
    let mut prompt = BrowserNeedsHumanPrompt::default();
    for tab in tabs {
        if browser_frame_belongs_to_project(store, &tab.frame_id, project_id).await? {
            prompt.tabs.push(tab.clone());
        }
    }
    Ok(prompt)
}

pub(crate) async fn emit_browser_needs_human(
    app: &tauri::AppHandle,
    tabs: &[BrowserNeedsHumanTab],
) {
    use tauri::{Emitter, Manager};
    let state = app.state::<crate::AppState>();
    for (label, window) in app.workspace_surfaces() {
        let project_id = crate::window_bound_project_id(&state, &label);
        if let Ok(prompt) =
            project_browser_needs_human(&state.store, tabs, project_id.as_deref()).await
        {
            if crate::window_bound_project_id(&state, &label) != project_id {
                continue;
            }
            // Empty snapshots also clear prompts after verification finishes.
            let _ = window.emit_to(&label, "browser-needs-human", prompt);
        }
    }
}

#[tauri::command]
pub async fn confirm_browser_tab_cleanup(
    state: tauri::State<'_, crate::AppState>,
    turn_id: String,
    tabs: Vec<BrowserTabCleanupItem>,
) -> Result<Vec<i64>, String> {
    if tabs.is_empty() {
        state.browser_bridge.dismiss_cleanup(&turn_id).await;
        return Ok(Vec::new());
    }
    state.browser_bridge.confirm_cleanup(&turn_id, &tabs).await
}

#[tauri::command]
pub async fn dismiss_browser_tab_cleanup(
    state: tauri::State<'_, crate::AppState>,
    turn_id: String,
) -> Result<(), String> {
    state.browser_bridge.dismiss_cleanup(&turn_id).await;
    Ok(())
}

#[tauri::command]
pub async fn list_pending_browser_needs_human(
    state: tauri::State<'_, crate::AppState>,
    window: crate::workspace_surface::WorkspaceSurface,
) -> Result<BrowserNeedsHumanPrompt, String> {
    let project_id = crate::window_bound_project_id(&state, window.label());
    let prompt = state.browser_bridge.list_needs_human().await;
    project_browser_needs_human(&state.store, &prompt.tabs, project_id.as_deref()).await
}

#[tauri::command]
pub async fn confirm_browser_needs_human(
    state: tauri::State<'_, crate::AppState>,
    window: crate::workspace_surface::WorkspaceSurface,
    tabs: Vec<BrowserNeedsHumanTab>,
) -> Result<BrowserNeedsHumanConfirmResult, String> {
    let project_id = crate::window_bound_project_id(&state, window.label());
    state
        .browser_bridge
        .confirm_needs_human_for_project(&state.store, project_id.as_deref(), &tabs)
        .await
}

#[tauri::command]
pub async fn focus_browser_needs_human(
    state: tauri::State<'_, crate::AppState>,
    window: crate::workspace_surface::WorkspaceSurface,
    session: String,
    tab_id: i64,
) -> Result<(), String> {
    let project_id = crate::window_bound_project_id(&state, window.label());
    state
        .browser_bridge
        .focus_needs_human_for_project(&state.store, project_id.as_deref(), &session, tab_id)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use sha2::{Digest, Sha256};

    #[tokio::test]
    async fn pending_browser_prompts_only_belong_to_the_bound_project() {
        let (store, path) = empty_store().await;
        let bridge = BrowserBridge::new(PathBuf::from("."));
        let mut tabs = Vec::new();
        for id in ["a", "b"] {
            store
                .create_project(id, id, &format!("/ws/{id}"))
                .await
                .unwrap();
            store.create_frame(id, id, "OPERON", "model").await.unwrap();
            bridge
                .stash_pending(
                    BrowserTabCleanupPrompt {
                        frame_id: id.into(),
                        turn_id: id.into(),
                        tabs: vec![BrowserTabCleanupItem {
                            tab_id: 11,
                            ..Default::default()
                        }],
                    },
                    false,
                )
                .await;
            tabs.push(BrowserNeedsHumanTab {
                frame_id: id.into(),
                ..Default::default()
            });
        }
        for id in ["a", "b"] {
            let cleanups = bridge
                .project_pending_cleanups(&store, Some(id))
                .await
                .unwrap();
            assert_eq!(cleanups.len(), 1);
            assert_eq!(cleanups[0].frame_id, id);
            let human = project_browser_needs_human(&store, &tabs, Some(id))
                .await
                .unwrap();
            assert_eq!(human.tabs.len(), 1);
            assert_eq!(human.tabs[0].frame_id, id);
        }
        for project_id in [None, Some("unrelated")] {
            assert!(bridge
                .project_pending_cleanups(&store, project_id)
                .await
                .unwrap()
                .is_empty());
            assert!(project_browser_needs_human(&store, &tabs, project_id)
                .await
                .unwrap()
                .tabs
                .is_empty());
        }
        store.delete_project("a").await.unwrap();
        assert!(bridge
            .project_pending_cleanups(&store, Some("a"))
            .await
            .unwrap()
            .is_empty());
        drop(store);
        let _ = std::fs::remove_file(path);
    }

    struct NoEnv(PathBuf);

    #[async_trait]
    impl ToolEnv for NoEnv {
        fn project_root(&self) -> &std::path::Path {
            &self.0
        }

        async fn confirm(&self, _message: &str) -> bool {
            true
        }

        async fn emit(&self, _event: wisp_tools::ToolEvent) {}
    }

    struct OccupancyEnv {
        root: PathBuf,
        project_id: Option<String>,
        turn_id: Option<String>,
    }

    impl OccupancyEnv {
        fn new(project_id: &str, turn_id: &str) -> Self {
            Self {
                root: PathBuf::from("."),
                project_id: Some(project_id.into()),
                turn_id: Some(turn_id.into()),
            }
        }
    }

    #[async_trait]
    impl ToolEnv for OccupancyEnv {
        fn project_root(&self) -> &std::path::Path {
            &self.root
        }
        async fn confirm(&self, _message: &str) -> bool {
            true
        }
        async fn emit(&self, _event: wisp_tools::ToolEvent) {}
        fn turn_id(&self) -> Option<&str> {
            self.turn_id.as_deref()
        }
        fn project_id(&self) -> Option<&str> {
            self.project_id.as_deref()
        }
    }

    #[test]
    fn occupancy_reenters_same_project_and_blocks_foreign_until_release() {
        let bridge = BrowserBridge::new(PathBuf::from("extension"));
        bridge.occupy_turn("shared", "proj-a", "turn-1").unwrap();
        bridge.occupy_turn("shared", "proj-a", "turn-2").unwrap();
        let error = bridge
            .occupy_turn("shared", "proj-b", "turn-3")
            .unwrap_err();
        assert!(
            error.contains("another project"),
            "foreign project should see occupancy: {error}"
        );
        assert!(error.contains("proj-a"), "{error}");
        assert!(error.contains("'shared'"), "{error}");
        bridge.release_turn("turn-1");
        let still_held = bridge
            .occupy_turn("shared", "proj-b", "turn-3")
            .unwrap_err();
        assert!(still_held.contains("proj-a"), "{still_held}");
        bridge.release_turn("turn-2");
        bridge.occupy_turn("shared", "proj-b", "turn-3").unwrap();
    }

    #[test]
    fn occupancy_allows_foreign_projects_on_independent_sessions() {
        let bridge = BrowserBridge::new(PathBuf::from("extension"));
        bridge.occupy_turn("shared", "proj-a", "turn-a").unwrap();
        bridge.occupy_turn("workspace", "proj-b", "turn-b").unwrap();

        let shared_error = bridge
            .occupy_turn("shared", "proj-c", "turn-c")
            .unwrap_err();
        assert!(shared_error.contains("proj-a"), "{shared_error}");
        let workspace_error = bridge
            .occupy_turn("workspace", "proj-c", "turn-c")
            .unwrap_err();
        assert!(workspace_error.contains("proj-b"), "{workspace_error}");

        bridge.release_turn("turn-a");
        bridge.occupy_turn("shared", "proj-c", "turn-c").unwrap();
        let workspace_still_held = bridge
            .occupy_turn("workspace", "proj-c", "turn-c")
            .unwrap_err();
        assert!(workspace_still_held.contains("proj-b"));
    }

    #[tokio::test]
    async fn occupancy_complete_turn_releases_holder() {
        let bridge = BrowserBridge::new(PathBuf::from("extension"));
        bridge.occupy_turn("workspace", "proj-a", "turn-a").unwrap();
        assert!(matches!(
            bridge.complete_turn("turn-a").await,
            TabCleanupAction::None
        ));
        bridge.occupy_turn("workspace", "proj-b", "turn-b").unwrap();
    }

    #[test]
    fn occupancy_holds_across_two_tools_in_one_turn() {
        let bridge = BrowserBridge::new(PathBuf::from("extension"));
        let env = OccupancyEnv::new("proj-a", "turn-1");
        occupy_or_fail(&bridge, &env, None).unwrap();
        occupy_or_fail(&bridge, &env, Some("shared")).unwrap();
        let foreign = OccupancyEnv::new("proj-b", "turn-2");
        let fail = occupy_or_fail(&bridge, &foreign, None).unwrap_err();
        assert!(!fail.success);
        assert!(
            fail.content.contains("proj-a"),
            "foreign project should see occupying id: {}",
            fail.content
        );
        assert!(fail.content.contains("another project"), "{}", fail.content);
    }

    #[tokio::test]
    async fn browser_tools_lease_the_resolved_session_independently() {
        let bridge = Arc::new(BrowserBridge::new(PathBuf::from("extension")));
        let (shared_tx, _shared_rx) = mpsc::unbounded_channel();
        let (workspace_tx, _workspace_rx) = mpsc::unbounded_channel();
        bridge.install_client_on(1, shared_tx, "shared").await;
        let identity = project_workspace::tests::register_fake(&bridge, "proj-b")
            .await
            .0;
        bridge
            .install_client_on(2, workspace_tx, &identity.lane)
            .await;

        let shared = WebScanTool::new(bridge.clone())
            .run(
                &json!({ "tabs_only": true }),
                &OccupancyEnv::new("proj-a", "turn-a"),
            )
            .await;
        assert!(shared.success, "{}", shared.content);

        let workspace = WebScanTool::new(bridge.clone())
            .run(
                &json!({ "tabs_only": true, "session": "workspace" }),
                &OccupancyEnv::new("proj-b", "turn-b"),
            )
            .await;
        assert!(workspace.success, "{}", workspace.content);

        let blocked_shared = WebScanTool::new(bridge)
            .run(
                &json!({ "tabs_only": true, "session": "shared" }),
                &OccupancyEnv::new("proj-c", "turn-c"),
            )
            .await;
        assert!(!blocked_shared.success);
        assert!(blocked_shared.content.contains("proj-a"));
        assert!(blocked_shared.content.contains("'shared'"));
    }

    #[tokio::test]
    async fn invalid_session_does_not_claim_the_default_shared_lease() {
        let bridge = Arc::new(BrowserBridge::new(PathBuf::from("extension")));
        let (shared_tx, _shared_rx) = mpsc::unbounded_channel();
        bridge.install_client_on(1, shared_tx, "shared").await;

        let invalid = WebScanTool::new(bridge.clone())
            .run(
                &json!({ "tabs_only": true, "session": "invalid" }),
                &OccupancyEnv::new("proj-a", "turn-a"),
            )
            .await;
        assert!(!invalid.success);
        assert!(invalid
            .content
            .contains("session must be shared or workspace"));

        let shared = WebScanTool::new(bridge)
            .run(
                &json!({ "tabs_only": true }),
                &OccupancyEnv::new("proj-b", "turn-b"),
            )
            .await;
        assert!(shared.success, "{}", shared.content);
    }

    #[test]
    fn occupancy_skips_envs_without_project_or_turn() {
        let bridge = BrowserBridge::new(PathBuf::from("extension"));
        let no_project = OccupancyEnv {
            root: PathBuf::from("."),
            project_id: None,
            turn_id: Some("turn-1".into()),
        };
        occupy_or_fail(&bridge, &no_project, None).unwrap();
        occupy_or_fail(&bridge, &NoEnv(PathBuf::from(".")), None).unwrap();

        occupy_or_fail(&bridge, &OccupancyEnv::new("proj-a", "turn-1"), None).unwrap();
        occupy_or_fail(&bridge, &no_project, Some("workspace")).unwrap();
        occupy_or_fail(&bridge, &NoEnv(PathBuf::from(".")), Some("workspace")).unwrap();
        occupy_or_fail(
            &bridge,
            &OccupancyEnv {
                root: PathBuf::from("."),
                project_id: Some(String::new()),
                turn_id: Some("turn-2".into()),
            },
            Some("workspace"),
        )
        .unwrap();
        occupy_or_fail(
            &bridge,
            &OccupancyEnv {
                root: PathBuf::from("."),
                project_id: Some("proj-b".into()),
                turn_id: None,
            },
            Some("workspace"),
        )
        .unwrap();
        occupy_or_fail(
            &bridge,
            &OccupancyEnv {
                root: PathBuf::from("."),
                project_id: Some("proj-b".into()),
                turn_id: Some(String::new()),
            },
            Some("workspace"),
        )
        .unwrap();
        let fail =
            occupy_or_fail(&bridge, &OccupancyEnv::new("proj-b", "turn-3"), None).unwrap_err();
        assert!(
            fail.content.contains("proj-a"),
            "skipping the lock must not release it: {}",
            fail.content
        );
    }

    async fn empty_store() -> (Store, PathBuf) {
        let tmp =
            std::env::temp_dir().join(format!("wisp_browser_tool_{}.sqlite", uuid::Uuid::new_v4()));
        (Store::open(&tmp).await.unwrap(), tmp)
    }

    #[test]
    fn manifest_key_matches_the_only_accepted_extension_origin() {
        let manifest_path = wisp_paths::browser_extension_dir()
            .unwrap()
            .join("manifest.json");
        let manifest: Value =
            serde_json::from_slice(&std::fs::read(manifest_path).unwrap()).unwrap();
        let key = manifest["key"].as_str().unwrap();
        let der = base64::engine::general_purpose::STANDARD
            .decode(key)
            .unwrap();
        let digest = Sha256::digest(der);
        let id: String = digest[..16]
            .iter()
            .flat_map(|byte| [byte >> 4, byte & 0x0f])
            .map(|nibble| char::from(b'a' + nibble))
            .collect();
        assert_eq!(EXTENSION_ORIGIN, format!("chrome-extension://{id}"));
    }

    #[test]
    fn bridge_accepts_extension_origins_only() {
        assert!(allowed_extension_origin(Some(
            "chrome-extension://gnkjgagleagkgdlkkcianolobfdoocnp"
        )));
        assert!(!allowed_extension_origin(Some(
            "chrome-extension://abcdefghijklmnop"
        )));
        assert!(!allowed_extension_origin(Some("https://example.com")));
        assert!(!allowed_extension_origin(Some("null")));
        assert!(!allowed_extension_origin(None));
    }

    #[tokio::test]
    async fn page_access_tools_always_require_approval() {
        let bridge = Arc::new(BrowserBridge::new(PathBuf::from("extension")));
        let (store, tmp) = empty_store().await;
        assert_eq!(
            WebScanTool::new(bridge.clone()).minimum_approval(),
            Approval::Ask
        );
        assert_eq!(
            WebExecuteJsTool::new(bridge.clone(), store).minimum_approval(),
            Approval::Ask
        );
        assert_eq!(
            WebScreenshotTool::new(bridge).minimum_approval(),
            Approval::Ask
        );
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn extension_connection_status_tracks_live_clients() {
        let bridge = BrowserBridge::new(PathBuf::from("extension"));
        assert!(!bridge.extension_connected().await);

        let (tx, _rx) = mpsc::unbounded_channel();
        bridge.install_client(7, tx).await;
        assert!(bridge.extension_connected().await);

        bridge.disconnect_client(7).await;
        assert!(!bridge.extension_connected().await);
    }

    #[tokio::test]
    async fn execute_js_rejects_window_close_with_the_tab_command() {
        let bridge = Arc::new(BrowserBridge::new(PathBuf::from("extension")));
        let (store, tmp) = empty_store().await;
        let result = WebExecuteJsTool::new(bridge, store)
            .run(
                &json!({ "script": "window.close(); 'close-requested'" }),
                &NoEnv(PathBuf::from(".")),
            )
            .await;
        assert!(!result.success);
        assert!(result.content.contains("\"method\":\"close\""));
        assert!(result.content.contains("tabIds"));
        let _ = std::fs::remove_file(tmp);
    }

    #[test]
    fn are_you_a_robot_page_requires_manual_handoff() {
        let handoff = human_verification_handoff(&json!({
            "title": "Are you a robot?",
            "text": "Please confirm you are a human by completing the captcha challenge below."
        }))
        .unwrap();

        assert_eq!(handoff["required"], true);
        assert_eq!(handoff["reason"], "captcha_challenge");
        assert!(handoff["instruction"]
            .as_str()
            .unwrap()
            .contains("verification prompt"));
        assert!(handoff["instruction"]
            .as_str()
            .unwrap()
            .contains("Do not call ask_user"));
        assert!(human_verification_handoff(&json!({
            "title": "Browser automation article",
            "text": "This article asks: Are you a robot?"
        }))
        .is_none());
        let sciencedirect = human_verification_handoff(&json!({
            "title": "Just a moment...",
            "url": "https://www.sciencedirect.com/science/article/pii/S000",
            "text": "Are you a robot?\nPlease confirm you are a human by completing the captcha challenge below."
        }))
        .unwrap();
        assert_eq!(sciencedirect["reason"], "captcha_challenge");
    }

    #[tokio::test]
    async fn setup_reports_the_extension_folder_without_requiring_approval() {
        let extension_dir = wisp_paths::browser_extension_dir().unwrap();
        let bridge = Arc::new(BrowserBridge::new(extension_dir.clone()));
        let (store, tmp) = empty_store().await;
        let info = bridge.setup_info().await;
        let expected_path = dunce::canonicalize(extension_dir).unwrap();

        assert_eq!(info["status"], "disconnected");
        assert_eq!(info["live_retrieval"], false);
        assert_eq!(info["code"], BROWSER_DISCONNECTED_CODE);
        assert_eq!(info["required_protocol"], 2);
        assert_eq!(info["bundled_extension_version"], "0.4.3");
        assert_eq!(info["extension_version"], "0.4.3");
        assert!(info["assistant_instruction"]
            .as_str()
            .unwrap()
            .contains("Do not answer live, latest, current, or URL-specific questions"));
        assert_eq!(info["runtime_os"], std::env::consts::OS);
        assert_eq!(info["path_source"], "wisp_tauri_resource_dir");
        assert_eq!(info["extension_path"], expected_path.display().to_string());
        assert_eq!(info["extension_path_verified"], true);
        assert_eq!(info["install_scope"], "once_per_browser_profile");
        assert_eq!(info["auto_launch_browser"], false);
        assert_eq!(info["auto_close_tabs"], false);
        assert_eq!(
            info["download_automation"]["chrome_settings_url"],
            "chrome://settings/downloads"
        );
        assert_eq!(
            info["download_automation"]["setting_to_disable"],
            "Ask where to save each file before downloading"
        );
        assert_eq!(
            info["download_automation"]["multiple_downloads"]["chrome_settings_url"],
            "chrome://settings/content/automaticDownloads"
        );
        assert!(
            info["download_automation"]["multiple_downloads"]["recommended_action"]
                .as_str()
                .unwrap()
                .contains("trusted target site")
        );
        assert!(
            info["download_automation"]["multiple_downloads"]["agent_gate"]
                .as_str()
                .unwrap()
                .contains("wait for the user to confirm")
        );
        assert!(WebExecuteJsTool::new(bridge.clone(), store.clone())
            .schema()
            .function
            .description
            .contains("until confirmed, trigger at most one file download"));
        assert!(info["steps"].as_array().unwrap().iter().any(|step| step
            .as_str()
            .unwrap()
            .contains(info["extension_path"].as_str().unwrap())));
        let unavailable = bridge.unavailable_message("not connected");
        assert!(unavailable.contains(info["extension_path"].as_str().unwrap()));
        assert!(unavailable.contains(BROWSER_DISCONNECTED_MARKER));
        assert!(
            unavailable.contains("Do not answer live, latest, current, or URL-specific questions")
        );
        assert_eq!(
            BrowserSetupTool::new(bridge, store).minimum_approval(),
            Approval::Allow
        );
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn setup_never_offers_an_unverified_extension_path() {
        let missing = std::env::temp_dir().join(format!(
            "wisp-browser-extension-missing-{}",
            std::process::id()
        ));
        let bridge = BrowserBridge::new(missing.clone());
        let info = bridge.setup_info().await;

        assert_eq!(info["status"], "extension_missing");
        assert_eq!(info["live_retrieval"], false);
        assert_eq!(info["code"], BROWSER_DISCONNECTED_CODE);
        assert_eq!(info["extension_path_verified"], false);
        assert!(info["extension_path"].is_null());
        assert!(info["steps"].as_array().unwrap().is_empty());
        assert!(!bridge
            .unavailable_message("not connected")
            .contains(&missing.display().to_string()));

        let incomplete = std::env::temp_dir().join(format!(
            "wisp-browser-extension-incomplete-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&incomplete).unwrap();
        std::fs::write(incomplete.join("manifest.json"), "{}").unwrap();
        let incomplete_bridge = BrowserBridge::new(incomplete.clone());
        let incomplete_info = incomplete_bridge.setup_info().await;
        assert_eq!(incomplete_info["status"], "extension_missing");
        assert!(incomplete_info["extension_path"].is_null());
        let _ = std::fs::remove_dir_all(&incomplete);
    }

    #[test]
    fn extension_page_url_matches_the_browser_scheme() {
        // Windows/Linux executables identify the browser by file stem.
        assert_eq!(
            extensions_page_url(Path::new("chrome"), &[]),
            "chrome://extensions"
        );
        assert_eq!(
            extensions_page_url(Path::new("chromium"), &[]),
            "chrome://extensions"
        );
        assert_eq!(
            extensions_page_url(Path::new("msedge"), &[]),
            "edge://extensions"
        );
        assert_eq!(
            extensions_page_url(Path::new("microsoft-edge-stable"), &[]),
            "edge://extensions"
        );
        assert_eq!(
            extensions_page_url(Path::new("brave"), &[]),
            "brave://extensions"
        );
        // macOS goes through `open -a "<App Name>"`, so the identity is an arg.
        let open = Path::new("/usr/bin/open");
        assert_eq!(
            extensions_page_url(open, &["-a".into(), "Google Chrome".into()]),
            "chrome://extensions"
        );
        assert_eq!(
            extensions_page_url(open, &["-a".into(), "Microsoft Edge".into()]),
            "edge://extensions"
        );
        assert_eq!(
            extensions_page_url(open, &["-a".into(), "Brave Browser".into()]),
            "brave://extensions"
        );
        assert_eq!(
            extension_page_launch_args(open, vec!["-a".into(), "Google Chrome".into()]),
            vec![
                "-a".to_string(),
                "Google Chrome".into(),
                "--args".into(),
                "chrome://extensions".into(),
            ]
        );
        assert_eq!(
            extension_page_launch_args(Path::new("msedge"), Vec::new()),
            vec!["edge://extensions".to_string()]
        );
    }

    #[test]
    fn extension_setup_never_launches_a_browser_from_tests() {
        let missing = std::env::temp_dir().join(format!(
            "wisp-browser-extension-setup-missing-{}",
            std::process::id()
        ));
        let bridge = BrowserBridge::new(missing);
        let setup = bridge.open_extension_setup();

        assert!(!setup.opened);
        assert!(setup.extension_path.is_none());
    }

    #[test]
    fn tab_parser_accepts_generic_agent_numeric_and_string_ids() {
        let numeric =
            parse_tab(&json!({ "id": 7, "url": "https://a", "title": "A", "active": true }))
                .unwrap();
        let string = parse_tab(&json!({ "id": "8", "url": "https://b", "title": "B" })).unwrap();
        assert_eq!(numeric.id, 7);
        assert!(numeric.active);
        assert_eq!(string.id, 8);
    }

    #[tokio::test]
    async fn routes_execution_to_the_live_extension_and_correlates_result() {
        let bridge = Arc::new(BrowserBridge::new(PathBuf::from("extension")));
        let (tx, mut rx) = mpsc::unbounded_channel();
        bridge.install_client(1, tx).await;
        bridge
            .handle_text(
                1,
                r#"{"type":"ext_ready","tabs":[{"id":42,"url":"https://example.com","title":"Example","active":true}]}"#,
            )
            .await;

        let running = {
            let bridge = bridge.clone();
            tokio::spawn(async move {
                bridge
                    .execute(None, "document.title", Duration::from_secs(1))
                    .await
            })
        };
        let outbound = rx.recv().await.unwrap().into_text().unwrap();
        let outbound: Value = serde_json::from_str(&outbound).unwrap();
        assert_eq!(outbound["tabId"], 42);
        assert_eq!(outbound["code"], "document.title");
        assert_eq!(outbound["timeoutMs"], 1000);
        let id = outbound["id"].as_str().unwrap();
        bridge
            .handle_text(
                1,
                &json!({ "type": "result", "id": id, "result": "Example" }).to_string(),
            )
            .await;

        let result = running.await.unwrap().unwrap();
        assert_eq!(result.tab_id, 42);
        assert_eq!(result.value, "Example");
    }

    #[tokio::test]
    async fn json_ping_from_the_registered_extension_is_answered_with_a_pong() {
        let bridge = Arc::new(BrowserBridge::new(PathBuf::from("extension")));
        let (tx, mut rx) = mpsc::unbounded_channel();
        bridge.install_client(1, tx).await;

        bridge
            .handle_text(1, r#"{"type":"ping","session":"shared"}"#)
            .await;

        let reply = rx.recv().await.unwrap().into_text().unwrap();
        let reply: Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(reply["type"], "pong");
        assert_eq!(reply["session"], "shared");
        assert!(
            reply.get("id").is_none(),
            "pong must not look like a request"
        );
    }

    #[tokio::test]
    async fn a_new_registration_closes_the_replaced_socket_and_stops_answering_it() {
        let bridge = Arc::new(BrowserBridge::new(PathBuf::from("extension")));
        let (old_tx, mut old_rx) = mpsc::unbounded_channel();
        bridge.install_client(1, old_tx).await;
        let (new_tx, mut new_rx) = mpsc::unbounded_channel();
        bridge.install_client(2, new_tx).await;

        assert!(
            matches!(old_rx.recv().await, Some(Message::Close(_))),
            "the superseded connection must be told to close"
        );

        bridge
            .handle_text(1, r#"{"type":"ping","session":"shared"}"#)
            .await;
        assert!(
            old_rx.try_recv().is_err(),
            "a stale connection's ping gets no pong"
        );

        bridge
            .handle_text(2, r#"{"type":"ping","session":"shared"}"#)
            .await;
        let reply = new_rx.recv().await.unwrap().into_text().unwrap();
        assert!(reply.contains("\"pong\""), "{reply}");
    }

    #[tokio::test]
    async fn side_panel_messages_go_to_the_app_with_the_asking_connection() {
        let bridge = Arc::new(BrowserBridge::new(PathBuf::from("extension")));
        let (client_tx, mut client_rx) = mpsc::unbounded_channel();
        bridge.install_client(1, client_tx).await;
        let (sink, mut requests) = mpsc::unbounded_channel();
        bridge.set_side_panel_sink(sink).await;

        let ask = json!({ "type": "side_ask", "id": "a1", "question": "Is the data public?" });
        // A connection that was replaced must not start turns.
        bridge.handle_text(2, &ask.to_string()).await;
        assert!(requests.try_recv().is_err());

        bridge.handle_text(1, &ask.to_string()).await;
        let request = requests.try_recv().unwrap();
        assert_eq!(request.message, ask);
        request
            .reply
            .send(Message::Text(r#"{"type":"side_done","id":"a1"}"#.into()))
            .unwrap();
        let reply = client_rx.recv().await.unwrap().into_text().unwrap();
        assert!(reply.as_str().contains("side_done"));
        // Side panel traffic never resolves a pending browser command.
        assert!(client_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn open_tab_creates_a_tab_without_any_existing_tab() {
        let bridge = Arc::new(BrowserBridge::new(PathBuf::from("extension")));
        let (tx, mut rx) = mpsc::unbounded_channel();
        bridge.install_client(1, tx).await;
        // No tabs_update sent: state.tabs is empty, yet open_tab must still work.

        let running = {
            let bridge = bridge.clone();
            tokio::spawn(async move { bridge.open_tab("https://example.com", true).await })
        };
        let outbound = rx.recv().await.unwrap().into_text().unwrap();
        let outbound: Value = serde_json::from_str(&outbound).unwrap();
        assert!(outbound.get("tabId").is_none());
        assert_eq!(outbound["timeoutMs"], DEFAULT_TIMEOUT_MS);
        let command: Value = serde_json::from_str(outbound["code"].as_str().unwrap()).unwrap();
        assert_eq!(command["cmd"], "tabs");
        assert_eq!(command["method"], "create");
        assert_eq!(command["url"], "https://example.com");
        assert_eq!(command["active"], true);

        let id = outbound["id"].as_str().unwrap();
        bridge
            .handle_text(
                1,
                &json!({ "type": "result", "id": id, "result": { "id": 99, "url": "https://example.com" } })
                    .to_string(),
            )
            .await;

        let reply = running.await.unwrap().unwrap();
        assert_eq!(reply.value["id"], 99);
        assert!(reply.ready.is_none());
        assert!(reply.wait.is_none());
    }

    #[tokio::test]
    async fn open_tab_and_execute_js_refuse_blocked_hosts() {
        let bridge = Arc::new(BrowserBridge::new(PathBuf::from("extension")));
        let (store, tmp) = empty_store().await;
        crate::browser_url_filters::save(
            &store,
            BrowserUrlFilters {
                block: vec![crate::browser_url_filters::BrowserUrlFilterRule {
                    host: "blocked.test".into(),
                    reason: "hijacked".into(),
                }],
                prefer: vec![crate::browser_url_filters::BrowserUrlFilterRule {
                    host: "pubmed.ncbi.nlm.nih.gov".into(),
                    reason: String::new(),
                }],
            },
        )
        .await
        .unwrap();

        let opened = WebOpenTabTool::new(bridge.clone(), store.clone())
            .run(
                &json!({ "url": "https://www.blocked.test/paper" }),
                &NoEnv(PathBuf::from(".")),
            )
            .await;
        assert!(!opened.success);
        assert!(opened.content.contains("hijacked"));
        assert!(opened.content.contains("blocked.test"));

        let navigated = WebExecuteJsTool::new(bridge.clone(), store.clone())
            .run(
                &json!({ "script": "location.href='https://blocked.test/js'" }),
                &NoEnv(PathBuf::from(".")),
            )
            .await;
        assert!(!navigated.success);
        assert!(navigated.content.contains("blocked by user URL filter"));

        let setup = BrowserSetupTool::new(bridge, store)
            .run(&json!({}), &NoEnv(PathBuf::from(".")))
            .await;
        assert!(setup.success);
        assert!(setup.content.contains("blocked.test"));
        assert!(setup.content.contains("pubmed.ncbi.nlm.nih.gov"));
        let _ = std::fs::remove_file(tmp);
    }

    #[test]
    fn open_tab_result_flags_non_preferred_hosts() {
        let filters = BrowserUrlFilters {
            prefer: vec![crate::browser_url_filters::BrowserUrlFilterRule {
                host: "pubmed.ncbi.nlm.nih.gov".into(),
                reason: String::new(),
            }],
            ..BrowserUrlFilters::default()
        };
        let flagged = open_tab_result(
            BridgeReply {
                value: json!({ "id": 1 }),
                ready: None,
                wait: None,
                new_tabs: Vec::new(),
            },
            "https://scholar.google.com",
            &filters,
        );
        assert_eq!(flagged["preferred"], false);
        assert_eq!(flagged["prefer_hosts"][0], "pubmed.ncbi.nlm.nih.gov");
        let preferred = open_tab_result(
            BridgeReply {
                value: json!({ "id": 1 }),
                ready: Some(true),
                wait: Some(json!({ "until": "complete", "waited_ms": 12 })),
                new_tabs: Vec::new(),
            },
            "https://pubmed.ncbi.nlm.nih.gov/1",
            &filters,
        );
        assert_eq!(preferred["ready"], true);
        assert_eq!(preferred["wait"]["waited_ms"], 12);
        assert_eq!(preferred["preferred"], true);
        assert!(preferred.get("prefer_hosts").is_none());
    }

    #[tokio::test]
    async fn scan_and_open_surface_ready_wait_from_the_extension() {
        let bridge = Arc::new(BrowserBridge::new(PathBuf::from("extension")));
        let (tx, mut rx) = mpsc::unbounded_channel();
        bridge.install_client(1, tx).await;
        bridge
            .handle_text(
                1,
                r#"{"type":"ext_ready","tabs":[{"id":7,"url":"https://example.com","title":"Example","active":true}]}"#,
            )
            .await;

        let scanning = {
            let bridge = bridge.clone();
            tokio::spawn(async move {
                WebScanTool::new(bridge)
                    .run(&json!({}), &NoEnv(PathBuf::from(".")))
                    .await
            })
        };
        let outbound = rx.recv().await.unwrap().into_text().unwrap();
        let outbound: Value = serde_json::from_str(&outbound).unwrap();
        assert_eq!(outbound["timeoutMs"], DEFAULT_TIMEOUT_MS);
        let id = outbound["id"].as_str().unwrap();
        bridge
            .handle_text(
                1,
                &json!({
                    "type": "result",
                    "id": id,
                    "result": {
                        "url": "https://example.com",
                        "title": "Example",
                        "ready_state": "complete",
                        "text": "hello",
                        "elements": []
                    },
                    "ready": true,
                    "wait": { "until": "complete", "waited_ms": 80, "status": "complete" }
                })
                .to_string(),
            )
            .await;
        let scanned = scanning.await.unwrap();
        assert!(scanned.success);
        let body: Value = serde_json::from_str(&scanned.content).unwrap();
        assert_eq!(body["ready"], true);
        assert_eq!(body["wait"]["waited_ms"], 80);
        assert_eq!(body["page"]["ready_state"], "complete");

        let opening = {
            let bridge = bridge.clone();
            tokio::spawn(async move { bridge.open_tab("https://example.com/paper", false).await })
        };
        let outbound = rx.recv().await.unwrap().into_text().unwrap();
        let outbound: Value = serde_json::from_str(&outbound).unwrap();
        let id = outbound["id"].as_str().unwrap();
        bridge
            .handle_text(
                1,
                &json!({
                    "type": "result",
                    "id": id,
                    "result": { "id": 8, "url": "https://example.com/paper", "title": "Paper", "status": "loading" },
                    "ready": false,
                    "wait": { "until": "complete", "waited_ms": 14500, "timed_out": true, "status": "loading" }
                })
                .to_string(),
            )
            .await;
        let opened = opening.await.unwrap().unwrap();
        assert_eq!(opened.ready, Some(false));
        assert_eq!(opened.wait.as_ref().unwrap()["timed_out"], true);
        let rendered = open_tab_result(
            opened,
            "https://example.com/paper",
            &BrowserUrlFilters::default(),
        );
        assert_eq!(rendered["ready"], false);
        assert_eq!(rendered["tab"]["id"], 8);
    }

    #[test]
    fn scan_scripts_report_document_ready_state() {
        assert!(SCAN_SCRIPT.contains("ready_state: document.readyState"));
        assert!(TEXT_SCAN_SCRIPT.contains("ready_state: document.readyState"));
    }

    #[test]
    fn wait_tab_complete_matches_documented_contract() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../browser-extension");
        let output = std::process::Command::new("node")
            .args([
                "--test",
                "wait_tab.test.mjs",
                "protocol.test.mjs",
                "scan_page.test.mjs",
                "tab_ops.test.mjs",
                "wait_engine.test.mjs",
                "chat_adapter.test.mjs",
            ])
            .current_dir(&dir)
            .output()
            .expect("node --test should run the extension waiter contract");
        assert!(
            output.status.success(),
            "node --test wait_tab.test.mjs failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn browser_results_are_bounded_before_entering_model_context() {
        let rendered = render_json(&json!({ "text": "x".repeat(MAX_RESULT_CHARS * 2) }));
        assert!(rendered.chars().count() <= MAX_RESULT_CHARS + 40);
        assert!(rendered.ends_with("browser result truncated"));
    }

    #[tokio::test]
    async fn only_bridge_unavailability_carries_the_disconnect_marker() {
        let bridge = Arc::new(BrowserBridge::new(PathBuf::from("extension")));
        assert!(bridge
            .unavailable_message("browser extension is not connected")
            .contains(BROWSER_DISCONNECTED_MARKER));
        // A tab-level failure is not a disconnect and must not raise the
        // "no live retrieval" banner.
        let (tx, _rx) = mpsc::unbounded_channel();
        bridge.install_client(1, tx).await;
        let result = WebScanTool::new(bridge)
            .run(&json!({ "switch_tab_id": 9 }), &NoEnv(PathBuf::from(".")))
            .await;
        assert!(!result.success);
        assert!(!result.content.contains(BROWSER_DISCONNECTED_MARKER));
    }

    struct RecordingEnv {
        root: PathBuf,
        events: std::sync::Mutex<Vec<wisp_tools::ToolEvent>>,
    }

    #[async_trait]
    impl ToolEnv for RecordingEnv {
        fn project_root(&self) -> &std::path::Path {
            &self.root
        }

        async fn confirm(&self, _message: &str) -> bool {
            true
        }

        async fn emit(&self, event: wisp_tools::ToolEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    /// The tool result itself is the live-retrieval record the UI reads. A
    /// separate presentation event outlived the turn it described and revived a
    /// stale "no live retrieval" banner (#887, #921), so browser tools emit none.
    #[tokio::test]
    async fn disconnected_tools_mark_the_result_without_a_presentation() {
        let bridge = Arc::new(BrowserBridge::new(PathBuf::from("extension")));
        let env = RecordingEnv {
            root: PathBuf::from("."),
            events: std::sync::Mutex::new(Vec::new()),
        };
        let result = WebScanTool::new(bridge)
            .run(&json!({ "tabs_only": true }), &env)
            .await;
        assert!(!result.success);
        assert!(result.content.contains(BROWSER_DISCONNECTED_MARKER));
        assert!(env.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn omitted_session_prefers_shared_when_both_are_connected() {
        let bridge = Arc::new(BrowserBridge::new(PathBuf::from("extension")));
        let (tx_a, _rx_a) = mpsc::unbounded_channel();
        let (tx_b, _rx_b) = mpsc::unbounded_channel();
        bridge.install_client_on(1, tx_a, "shared").await;
        bridge.install_client_on(2, tx_b, "workspace").await;
        bridge
            .handle_text(
                2,
                r#"{"type":"ext_ready","tabs":[{"id":22,"url":"https://workspace.example","title":"Workspace","active":true}]}"#,
            )
            .await;
        let result = WebScanTool::new(bridge)
            .run(&json!({ "tabs_only": true }), &NoEnv(PathBuf::from(".")))
            .await;
        assert!(result.success, "{}", result.content);
        assert_eq!(
            serde_json::from_str::<Value>(&result.content).unwrap()["tabs"],
            json!([])
        );
    }

    #[tokio::test]
    async fn workspace_only_does_not_make_default_setup_connected() {
        let bridge = Arc::new(BrowserBridge::new(PathBuf::from("extension")));
        let (tx, _rx) = mpsc::unbounded_channel();
        bridge.install_client_on(1, tx, "workspace").await;

        let info = bridge.setup_info().await;
        assert_eq!(info["status"], "extension_missing");
        assert_eq!(info["live_retrieval"], false);
        assert!(info["sessions"]["workspace"].is_null());
        assert_eq!(info["sessions"]["shared"]["connected"], false);
        assert!(bridge.tabs_on(None).await.is_err());
        assert!(bridge.tabs_on(Some("workspace")).await.is_ok());
    }

    #[test]
    fn shared_launch_uses_normal_profile_and_new_tab_on_each_platform() {
        for (program, args, expected) in [
            ("chrome.exe", vec![], vec!["chrome://newtab/"]),
            ("msedge.exe", vec![], vec!["edge://newtab/"]),
            (
                "/usr/bin/open",
                vec!["-a", "Google Chrome"],
                vec!["-a", "Google Chrome", "--args", "chrome://newtab/"],
            ),
        ] {
            let actual = shared_browser_launch_args(
                Path::new(program),
                args.into_iter().map(String::from).collect(),
            );
            assert_eq!(actual, expected);
        }
    }

    #[tokio::test]
    async fn automatic_launch_targets_only_disconnected_shared() {
        let (store, tmp) = empty_store().await;
        let bridge =
            BrowserBridge::construct(PathBuf::from("extension"), Some(store.clone()), true);
        let (tx, _rx) = mpsc::unbounded_channel();
        bridge.install_client_on(1, tx, "workspace").await;
        let launches = std::sync::atomic::AtomicUsize::new(0);
        let launch = || {
            launches.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        };
        bridge
            .ensure_extension_with(Some("workspace"), launch, Duration::ZERO)
            .await;
        assert_eq!(launches.load(std::sync::atomic::Ordering::SeqCst), 0);
        bridge
            .ensure_extension_with(None, launch, Duration::ZERO)
            .await;
        assert_eq!(launches.load(std::sync::atomic::Ordering::SeqCst), 1);
        let (tx, _rx_shared) = mpsc::unbounded_channel();
        bridge.install_client_on(2, tx, "shared").await;
        bridge
            .ensure_extension_with(None, launch, Duration::ZERO)
            .await;
        assert_eq!(launches.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(bridge.state.lock().await.workspaces.is_empty());
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn blank_setup_action_is_a_shared_status_check() {
        let bridge = Arc::new(BrowserBridge::new(PathBuf::from("extension")));
        let (store, tmp) = empty_store().await;
        let tool = BrowserSetupTool::new(bridge, store);
        assert!(tool
            .schema()
            .function
            .description
            .contains("Workspace is never a fallback"));
        let result = tool
            .run(&json!({ "action": "  " }), &NoEnv(PathBuf::from(".")))
            .await;

        assert!(result.success, "{}", result.content);
        assert_eq!(
            serde_json::from_str::<Value>(&result.content).unwrap()["live_retrieval"],
            false
        );
        for url in ["file:///tmp/private", "javascript:alert(1)", "https://"] {
            let result = tool
                .run(&json!({ "url": url }), &NoEnv(PathBuf::from(".")))
                .await;
            assert!(!result.success, "{url}");
        }
        let _ = std::fs::remove_file(tmp);
    }

    #[test]
    fn article_scan_is_not_inlined_in_the_legacy_scan_script() {
        assert!(!SCAN_SCRIPT.contains("code_blocks"));
        let scan_js = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../browser-extension/scan_page.js"),
        )
        .unwrap();
        assert!(scan_js.contains("code_blocks"));
        assert!(scan_js.contains("images"));
    }

    #[tokio::test]
    async fn article_scan_rejects_a_stale_extension() {
        let bridge = Arc::new(BrowserBridge::new(PathBuf::from("extension")));
        let (tx, _rx) = mpsc::unbounded_channel();
        bridge.install_client(1, tx).await;
        bridge
            .handle_text(
                1,
                r#"{"type":"ext_ready","tabs":[{"id":1,"url":"https://example.com","title":"E","active":true}]}"#,
            )
            .await;
        let result = WebScanTool::new(bridge)
            .run(&json!({ "mode": "article" }), &NoEnv(PathBuf::from(".")))
            .await;
        assert!(!result.success);
        assert!(result.content.contains("EXTENSION_STALE"));
    }

    fn tab(id: i64, url: &str, active: bool) -> BrowserTab {
        BrowserTab {
            id,
            url: url.into(),
            title: url.into(),
            active,
            window_id: None,
        }
    }

    #[test]
    fn chat_tab_picks_supported_sites_and_rejects_lookalikes() {
        let chatgpt = tab(1, "https://chatgpt.com/c/1", false);
        let gemini = tab(2, "https://gemini.google.com/app", true);
        let google_ai = tab(3, "https://www.google.com/search?udm=50&q=rna", false);
        let other = tab(4, "https://example.com", true);
        let (id, site) = chat_tab(&[chatgpt.clone(), gemini.clone()], None).unwrap();
        assert_eq!(id, 2);
        assert_eq!(site, chat_site::ChatSite::Gemini);
        let (id, site) = chat_tab(&[chatgpt.clone(), other.clone()], None).unwrap();
        assert_eq!(id, 1);
        assert_eq!(site, chat_site::ChatSite::ChatGpt);
        let (id, site) = chat_tab(&[google_ai.clone(), other.clone()], Some(3)).unwrap();
        assert_eq!(id, 3);
        assert_eq!(site, chat_site::ChatSite::GoogleAi);
        assert!(chat_tab(&[other.clone()], None)
            .unwrap_err()
            .contains("chatgpt.com"));
        assert!(chat_tab(&[other.clone()], Some(4))
            .unwrap_err()
            .contains("not one of those chat sites"));
        assert!(
            chat_tab(&[tab(9, "https://chatgpt.com.evil.com/", true)], None)
                .unwrap_err()
                .contains("chatgpt.com")
        );
    }

    #[test]
    fn project_relative_path_rejects_traversal_and_absolute_paths() {
        let root = Path::new("/project");
        assert_eq!(
            project_relative_path(root, "browser-assets/shot.png").unwrap(),
            root.join("browser-assets/shot.png")
        );
        assert_eq!(
            project_relative_path(root, "./figures/a.png").unwrap(),
            root.join("./figures/a.png")
        );
        assert!(project_relative_path(root, "../outside.png").is_err());
        assert!(project_relative_path(root, "a/../../outside.png").is_err());
        assert!(project_relative_path(root, "/etc/passwd").is_err());
        assert!(project_relative_path(root, "").is_err());
        assert!(project_relative_path(root, "   ").is_err());
    }

    #[test]
    fn paused_check_parses_the_command_instead_of_sniffing_the_raw_string() {
        let background_js = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../browser-extension/background.js"),
        )
        .unwrap();
        assert!(!background_js.contains("indexOf('\"cmd\":\"control\"')"));
        assert!(background_js.contains("isControlCommand(command)"));
    }

    #[tokio::test]
    async fn a_connected_extension_outranks_an_unverifiable_bundled_copy() {
        let missing = std::env::temp_dir().join(format!(
            "wisp-browser-extension-connected-{}",
            uuid::Uuid::new_v4()
        ));
        let bridge = Arc::new(BrowserBridge::new(missing));
        let (tx, _rx) = mpsc::unbounded_channel();
        bridge.install_client(1, tx).await;
        let info = bridge.setup_info().await;

        assert_eq!(info["status"], "connected");
        assert_eq!(info["live_retrieval"], true);
        assert!(info["code"].is_null());
        assert_eq!(info["extension_path_verified"], false);
        assert_eq!(info["auto_launch_browser"], false);
        assert_eq!(info["auto_close_tabs"], false);
    }

    #[test]
    fn refused_connection_explains_why_a_connected_popup_is_not_claimed() {
        assert!(refusal_summary(None).is_null());

        let foreign = refusal_summary(Some(&RefusedConnection {
            session: "shared".into(),
            origin: Some("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()),
            reason: "HTTP error: 403 Forbidden".into(),
        }));
        assert_eq!(foreign["session"], "shared");
        assert_eq!(foreign["expected_origin"], EXTENSION_ORIGIN);
        assert_eq!(foreign["reason"], "HTTP error: 403 Forbidden");
        let explanation = foreign["explanation"].as_str().unwrap();
        assert!(explanation.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(explanation.contains("Connected to Wisp"));

        let unfinished = refusal_summary(Some(&RefusedConnection {
            session: "workspace".into(),
            origin: None,
            reason: "WebSocket protocol error: Handshake not finished".into(),
        }));
        assert!(unfinished["explanation"]
            .as_str()
            .unwrap()
            .contains("without completing the Wisp extension handshake"));
    }

    #[tokio::test]
    async fn setup_names_the_refusal_and_the_stale_reload_instead_of_only_connected_false() {
        let extension_dir = wisp_paths::browser_extension_dir().unwrap();
        let bridge = Arc::new(BrowserBridge::new(extension_dir));
        bridge.state.lock().await.last_refusal = Some(RefusedConnection {
            session: "shared".into(),
            origin: Some("chrome-extension://other".into()),
            reason: "HTTP error: 403 Forbidden".into(),
        });
        let info = bridge.setup_info().await;
        assert_eq!(
            info["refused_connection"]["origin"],
            "chrome-extension://other"
        );
        assert_eq!(info["reload_required"], false);

        // A protocol-1 extension connects and its popup reads Connected, so the
        // status must name the reload rather than looking healthy.
        let (tx, _rx) = mpsc::unbounded_channel();
        bridge.install_client(1, tx).await;
        bridge
            .handle_text(1, r#"{"type":"ext_ready","protocol_version":1,"tabs":[]}"#)
            .await;
        let info = bridge.setup_info().await;
        assert_eq!(info["reload_required"], true);
        assert_eq!(info["update_required"], true);
        assert_eq!(info["sessions"]["shared"]["reload_required"], true);
        assert!(info["assistant_instruction"]
            .as_str()
            .unwrap()
            .contains("action=update_extension"));

        let status = bridge.extension_status().await;
        assert!(status.connected);
        assert_eq!(status.current_version.as_deref(), Some("0.2.1"));
        assert_eq!(status.bundled_version.as_deref(), Some("0.4.3"));
        assert!(status.update_required);
        assert!(!status.automatic_reload_available);
        assert!(status.integrity_verified);

        let update = bridge.update_extension().await;
        assert_eq!(update.outcome, "manual_reload_required");
        assert!(!update.opened, "tests must not launch a real browser");
        assert!(update.status.update_required);
    }

    #[tokio::test]
    async fn compatible_extension_update_reloads_and_rechecks_the_handshake() {
        let extension_dir = wisp_paths::browser_extension_dir().unwrap();
        let bridge = Arc::new(BrowserBridge::new(extension_dir));
        let (tx, mut rx) = mpsc::unbounded_channel();
        bridge.install_client(1, tx).await;
        bridge
            .handle_text(
                1,
                &json!({
                    "type": "ext_ready",
                    "protocol_version": 2,
                    "extension_version": "0.3.0",
                    "capabilities": ["runtime_reload"],
                    "tabs": []
                })
                .to_string(),
            )
            .await;

        let running = {
            let bridge = bridge.clone();
            tokio::spawn(async move { bridge.update_extension().await })
        };
        let outbound = rx.recv().await.unwrap().into_text().unwrap();
        let outbound: Value = serde_json::from_str(&outbound).unwrap();
        let command: Value = serde_json::from_str(outbound["code"].as_str().unwrap()).unwrap();
        assert_eq!(command["cmd"], "runtime");
        assert_eq!(command["method"], "reload");
        bridge
            .handle_text(
                1,
                &json!({
                    "type": "result",
                    "id": outbound["id"],
                    "result": { "reloading": true }
                })
                .to_string(),
            )
            .await;

        bridge.disconnect_client(1).await;
        let (new_tx, _new_rx) = mpsc::unbounded_channel();
        bridge.install_client(2, new_tx).await;
        bridge
            .handle_text(
                2,
                &json!({
                    "type": "ext_ready",
                    "protocol_version": 2,
                    "extension_version": "0.4.3",
                    "capabilities": ["runtime_reload", "article_scan"],
                    "tabs": []
                })
                .to_string(),
            )
            .await;

        let update = running.await.unwrap();
        assert_eq!(update.outcome, "updated");
        assert!(update.status.connected);
        assert!(!update.status.update_required);
        assert_eq!(update.status.current_version.as_deref(), Some("0.4.3"));
    }

    #[test]
    fn launch_candidates_name_a_real_chrome_family_browser() {
        let candidates = browser_launch_candidates();
        assert!(!candidates.is_empty());
        let rendered: Vec<String> = candidates
            .iter()
            .map(|(program, args)| format!("{} {}", program.display(), args.join(" ")))
            .collect();
        let blob = rendered.join("\n").to_lowercase();
        assert!(
            blob.contains("chrome") || blob.contains("chromium") || blob.contains("msedge"),
            "expected a Chrome-family launch plan, got {blob}"
        );
        #[cfg(windows)]
        assert!(blob.contains("chrome.exe") || blob.contains("start"));
        #[cfg(target_os = "macos")]
        assert!(blob.contains("open") && blob.contains("google chrome"));
    }

    #[derive(Clone)]
    struct TurnEnv {
        root: PathBuf,
        turn_id: String,
        frame_id: String,
    }

    #[async_trait]
    impl ToolEnv for TurnEnv {
        fn project_id(&self) -> Option<&str> {
            Some("test-project")
        }
        fn project_root(&self) -> &std::path::Path {
            &self.root
        }
        async fn confirm(&self, _message: &str) -> bool {
            true
        }
        async fn emit(&self, _event: wisp_tools::ToolEvent) {}
        fn turn_id(&self) -> Option<&str> {
            Some(&self.turn_id)
        }
        fn frame_id(&self) -> Option<&str> {
            Some(&self.frame_id)
        }
    }

    async fn reply_scan(
        bridge: &BrowserBridge,
        rx: &mut mpsc::UnboundedReceiver<Message>,
        url: &str,
        title: &str,
        text: &str,
    ) {
        let outbound = rx.recv().await.unwrap().into_text().unwrap();
        let outbound: Value = serde_json::from_str(&outbound).unwrap();
        let id = outbound["id"].as_str().unwrap();
        bridge
            .handle_text(
                1,
                &json!({
                    "type": "result",
                    "id": id,
                    "result": {
                        "url": url,
                        "title": title,
                        "text": text,
                        "ready_state": "complete"
                    }
                })
                .to_string(),
            )
            .await;
    }

    fn captcha_text() -> &'static str {
        "Are you a robot? Please confirm you are a human by completing the captcha challenge below."
    }

    async fn reply_open_tab(
        bridge: &BrowserBridge,
        rx: &mut mpsc::UnboundedReceiver<Message>,
        tab_id: i64,
        url: &str,
        title: &str,
    ) {
        let outbound = rx.recv().await.unwrap().into_text().unwrap();
        let outbound: Value = serde_json::from_str(&outbound).unwrap();
        let id = outbound["id"].as_str().unwrap();
        bridge
            .handle_text(
                1,
                &json!({
                    "type": "result",
                    "id": id,
                    "result": { "id": tab_id, "url": url, "title": title, "active": false }
                })
                .to_string(),
            )
            .await;
    }

    async fn reply_close_tabs(
        bridge: &BrowserBridge,
        rx: &mut mpsc::UnboundedReceiver<Message>,
        closed: &[i64],
    ) {
        let outbound = rx.recv().await.unwrap().into_text().unwrap();
        let outbound: Value = serde_json::from_str(&outbound).unwrap();
        let command: Value = serde_json::from_str(outbound["code"].as_str().unwrap()).unwrap();
        assert_eq!(command["cmd"], "tabs");
        assert_eq!(command["method"], "close");
        let id = outbound["id"].as_str().unwrap();
        bridge
            .handle_text(
                1,
                &json!({
                    "type": "result",
                    "id": id,
                    "result": { "closed": closed, "remaining": [] }
                })
                .to_string(),
            )
            .await;
    }

    #[tokio::test]
    async fn complete_turn_prompts_for_tabs_wisp_opened_and_skips_preexisting() {
        let (store, tmp) = empty_store().await;
        let bridge = Arc::new(BrowserBridge::new_with_store(
            PathBuf::from("extension"),
            store.clone(),
        ));
        let (tx, mut rx) = mpsc::unbounded_channel();
        bridge.install_client(1, tx).await;
        bridge
            .handle_text(
                1,
                r#"{"type":"ext_ready","tabs":[{"id":42,"url":"https://already.example","title":"Mine","active":true}]}"#,
            )
            .await;

        let env = TurnEnv {
            root: PathBuf::from("."),
            turn_id: "turn-a".into(),
            frame_id: "frame-a".into(),
        };
        let opening = {
            let bridge = bridge.clone();
            let store = store.clone();
            let env = env.clone();
            tokio::spawn(async move {
                WebOpenTabTool::new(bridge, store)
                    .run(&json!({ "url": "https://paper.example/1" }), &env)
                    .await
            })
        };
        reply_open_tab(&bridge, &mut rx, 99, "https://paper.example/1", "Paper").await;
        assert!(opening.await.unwrap().success);

        match bridge.complete_turn("turn-a").await {
            TabCleanupAction::Prompt(prompt) => {
                assert_eq!(prompt.turn_id, "turn-a");
                assert_eq!(prompt.frame_id, "frame-a");
                assert_eq!(prompt.tabs.len(), 1);
                assert_eq!(prompt.tabs[0].tab_id, 99);
                assert_eq!(prompt.tabs[0].session, "shared");
                assert_eq!(prompt.tabs[0].url, "https://paper.example/1");
            }
            other => panic!("expected prompt, got {other:?}"),
        }
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn auto_close_closes_this_turn_only_and_skips_already_gone_tabs() {
        let (store, tmp) = empty_store().await;
        store
            .set_setting(browser_url_filters::AUTO_CLOSE_TABS_KEY, "true")
            .await
            .unwrap();
        let bridge = Arc::new(BrowserBridge::new_with_store(
            PathBuf::from("extension"),
            store.clone(),
        ));
        let (tx, mut rx) = mpsc::unbounded_channel();
        bridge.install_client(1, tx).await;

        let env = TurnEnv {
            root: PathBuf::from("."),
            turn_id: "turn-b".into(),
            frame_id: "frame-b".into(),
        };
        let first = {
            let bridge = bridge.clone();
            let store = store.clone();
            let env = env.clone();
            tokio::spawn(async move {
                WebOpenTabTool::new(bridge, store)
                    .run(&json!({ "url": "https://a.example" }), &env)
                    .await
            })
        };
        reply_open_tab(&bridge, &mut rx, 11, "https://a.example", "A").await;
        assert!(first.await.unwrap().success);

        let second = {
            let bridge = bridge.clone();
            let store = store.clone();
            let env = env.clone();
            tokio::spawn(async move {
                WebOpenTabTool::new(bridge, store)
                    .run(&json!({ "url": "https://b.example" }), &env)
                    .await
            })
        };
        reply_open_tab(&bridge, &mut rx, 12, "https://b.example", "B").await;
        assert!(second.await.unwrap().success);

        {
            let mut state = bridge.state.lock().await;
            state.sessions.get_mut("shared").unwrap().tabs.remove(&12);
        }

        let closing = {
            let bridge = bridge.clone();
            tokio::spawn(async move { bridge.complete_turn("turn-b").await })
        };
        reply_close_tabs(&bridge, &mut rx, &[11]).await;
        match closing.await.unwrap() {
            TabCleanupAction::Closed => {}
            other => panic!("expected closed, got {other:?}"),
        }
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn confirm_cleanup_closes_only_selected_ledger_tabs() {
        let (store, tmp) = empty_store().await;
        let bridge = Arc::new(BrowserBridge::new_with_store(
            PathBuf::from("extension"),
            store.clone(),
        ));
        let (tx, mut rx) = mpsc::unbounded_channel();
        bridge.install_client(1, tx).await;

        let env = TurnEnv {
            root: PathBuf::from("."),
            turn_id: "turn-c".into(),
            frame_id: "frame-c".into(),
        };
        for (id, url) in [(21, "https://keep.example"), (22, "https://close.example")] {
            let opening = {
                let bridge = bridge.clone();
                let store = store.clone();
                let env = env.clone();
                tokio::spawn(async move {
                    WebOpenTabTool::new(bridge, store)
                        .run(&json!({ "url": url }), &env)
                        .await
                })
            };
            reply_open_tab(&bridge, &mut rx, id, url, "T").await;
            assert!(opening.await.unwrap().success);
        }

        let TabCleanupAction::Prompt(prompt) = bridge.complete_turn("turn-c").await else {
            panic!("expected prompt");
        };
        assert_eq!(prompt.tabs.len(), 2);

        let selected: Vec<_> = prompt
            .tabs
            .iter()
            .filter(|tab| tab.tab_id == 22)
            .cloned()
            .collect();
        let confirming = {
            let bridge = bridge.clone();
            let selected = selected.clone();
            tokio::spawn(async move { bridge.confirm_cleanup("turn-c", &selected).await })
        };
        reply_close_tabs(&bridge, &mut rx, &[22]).await;
        let closed = confirming.await.unwrap().unwrap();
        assert_eq!(closed, vec![22]);
        assert!(bridge.list_pending_cleanups().await.is_empty());
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn sibling_turns_and_browser_sessions_do_not_share_ledgers() {
        let (store, tmp) = empty_store().await;
        let bridge = Arc::new(BrowserBridge::new_with_store(
            PathBuf::from("extension"),
            store.clone(),
        ));
        let (shared_tx, mut shared_rx) = mpsc::unbounded_channel();
        let (workspace_tx, mut workspace_rx) = mpsc::unbounded_channel();
        bridge.install_client_on(1, shared_tx, "shared").await;
        let identity = project_workspace::tests::register_fake(&bridge, "test-project")
            .await
            .0;
        bridge
            .install_client_on(2, workspace_tx, &identity.lane)
            .await;

        let parent = TurnEnv {
            root: PathBuf::from("."),
            turn_id: "parent".into(),
            frame_id: "parent-frame".into(),
        };
        let child = TurnEnv {
            root: PathBuf::from("."),
            turn_id: "child".into(),
            frame_id: "child-frame".into(),
        };

        let opening_parent = {
            let bridge = bridge.clone();
            let store = store.clone();
            let env = parent.clone();
            tokio::spawn(async move {
                WebOpenTabTool::new(bridge, store)
                    .run(
                        &json!({ "url": "https://shared.example", "session": "shared" }),
                        &env,
                    )
                    .await
            })
        };
        let outbound = shared_rx.recv().await.unwrap().into_text().unwrap();
        let outbound: Value = serde_json::from_str(&outbound).unwrap();
        let id = outbound["id"].as_str().unwrap();
        bridge
            .handle_text_on(
                1,
                "shared",
                &json!({
                    "type": "result",
                    "id": id,
                    "result": { "id": 31, "url": "https://shared.example", "title": "S" }
                })
                .to_string(),
            )
            .await;
        assert!(opening_parent.await.unwrap().success);

        let opening_child = {
            let bridge = bridge.clone();
            let store = store.clone();
            let env = child.clone();
            tokio::spawn(async move {
                WebOpenTabTool::new(bridge, store)
                    .run(
                        &json!({ "url": "https://workspace.example", "session": "workspace" }),
                        &env,
                    )
                    .await
            })
        };
        let outbound = workspace_rx.recv().await.unwrap().into_text().unwrap();
        let outbound: Value = serde_json::from_str(&outbound).unwrap();
        let id = outbound["id"].as_str().unwrap();
        bridge
            .handle_text_on(
                2,
                &identity.lane,
                &json!({
                    "type": "result",
                    "id": id,
                    "result": { "id": 31, "url": "https://workspace.example", "title": "W" }
                })
                .to_string(),
            )
            .await;
        assert!(opening_child.await.unwrap().success);

        let TabCleanupAction::Prompt(parent_prompt) = bridge.complete_turn("parent").await else {
            panic!("expected parent prompt");
        };
        assert_eq!(parent_prompt.tabs.len(), 1);
        assert_eq!(parent_prompt.tabs[0].session, "shared");
        assert_eq!(parent_prompt.tabs[0].tab_id, 31);

        let TabCleanupAction::Prompt(child_prompt) = bridge.complete_turn("child").await else {
            panic!("expected child prompt");
        };
        assert_eq!(child_prompt.tabs.len(), 1);
        assert_eq!(child_prompt.tabs[0].session, identity.lane);
        assert_eq!(child_prompt.tabs[0].tab_id, 31);
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn captcha_scan_marks_needs_human_and_skips_auto_close() {
        let (store, tmp) = empty_store().await;
        store
            .set_setting(browser_url_filters::AUTO_CLOSE_TABS_KEY, "true")
            .await
            .unwrap();
        let bridge = Arc::new(BrowserBridge::new_with_store(
            PathBuf::from("extension"),
            store.clone(),
        ));
        let (tx, mut rx) = mpsc::unbounded_channel();
        bridge.install_client(1, tx).await;

        let env = TurnEnv {
            root: PathBuf::from("."),
            turn_id: "turn-human".into(),
            frame_id: "frame-human".into(),
        };
        for (id, url, title) in [
            (11, "https://keep.example/paper", "Paper"),
            (
                12,
                "https://www.sciencedirect.com/science",
                "Just a moment...",
            ),
        ] {
            let opening = {
                let bridge = bridge.clone();
                let store = store.clone();
                let env = env.clone();
                tokio::spawn(async move {
                    WebOpenTabTool::new(bridge, store)
                        .run(&json!({ "url": url }), &env)
                        .await
                })
            };
            reply_open_tab(&bridge, &mut rx, id, url, title).await;
            assert!(opening.await.unwrap().success);
        }

        let scanning = {
            let bridge = bridge.clone();
            let env = env.clone();
            tokio::spawn(async move {
                WebScanTool::new(bridge)
                    .run(&json!({ "switch_tab_id": 12 }), &env)
                    .await
            })
        };
        reply_scan(
            &bridge,
            &mut rx,
            "https://www.sciencedirect.com/science",
            "Just a moment...",
            captcha_text(),
        )
        .await;
        let scan = scanning.await.unwrap();
        assert!(scan.success);
        assert!(scan.content.contains("\"required\": true"));
        let pending = bridge.list_needs_human().await;
        assert_eq!(pending.tabs.len(), 1);
        assert_eq!(pending.tabs[0].tab_id, 12);
        assert_eq!(pending.tabs[0].frame_id, "frame-human");

        let closing = {
            let bridge = bridge.clone();
            tokio::spawn(async move { bridge.complete_turn("turn-human").await })
        };
        reply_close_tabs(&bridge, &mut rx, &[11]).await;
        match closing.await.unwrap() {
            TabCleanupAction::Closed => {}
            other => panic!("expected closed, got {other:?}"),
        }
        assert_eq!(bridge.list_needs_human().await.tabs.len(), 1);
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn complete_turn_prompt_excludes_needs_human_tabs() {
        let (store, tmp) = empty_store().await;
        let bridge = Arc::new(BrowserBridge::new_with_store(
            PathBuf::from("extension"),
            store.clone(),
        ));
        let (tx, mut rx) = mpsc::unbounded_channel();
        bridge.install_client(1, tx).await;
        let env = TurnEnv {
            root: PathBuf::from("."),
            turn_id: "turn-prompt".into(),
            frame_id: "frame-prompt".into(),
        };
        for (id, url) in [(21, "https://keep.example"), (22, "https://robot.example")] {
            let opening = {
                let bridge = bridge.clone();
                let store = store.clone();
                let env = env.clone();
                tokio::spawn(async move {
                    WebOpenTabTool::new(bridge, store)
                        .run(&json!({ "url": url }), &env)
                        .await
                })
            };
            reply_open_tab(&bridge, &mut rx, id, url, "T").await;
            assert!(opening.await.unwrap().success);
        }
        let scanning = {
            let bridge = bridge.clone();
            let env = env.clone();
            tokio::spawn(async move {
                WebScanTool::new(bridge)
                    .run(&json!({ "switch_tab_id": 22 }), &env)
                    .await
            })
        };
        reply_scan(
            &bridge,
            &mut rx,
            "https://robot.example",
            "Are you a robot?",
            captcha_text(),
        )
        .await;
        assert!(scanning.await.unwrap().success);

        let TabCleanupAction::Prompt(prompt) = bridge.complete_turn("turn-prompt").await else {
            panic!("expected prompt");
        };
        assert_eq!(prompt.tabs.len(), 1);
        assert_eq!(prompt.tabs[0].tab_id, 21);
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn execute_js_is_refused_on_a_needs_human_tab() {
        let (store, tmp) = empty_store().await;
        let bridge = Arc::new(BrowserBridge::new_with_store(
            PathBuf::from("extension"),
            store.clone(),
        ));
        let (tx, mut rx) = mpsc::unbounded_channel();
        bridge.install_client(1, tx).await;
        let env = TurnEnv {
            root: PathBuf::from("."),
            turn_id: "turn-js".into(),
            frame_id: "frame-js".into(),
        };
        let opening = {
            let bridge = bridge.clone();
            let store = store.clone();
            let env = env.clone();
            tokio::spawn(async move {
                WebOpenTabTool::new(bridge, store)
                    .run(&json!({ "url": "https://robot.example" }), &env)
                    .await
            })
        };
        reply_open_tab(&bridge, &mut rx, 33, "https://robot.example", "Robot").await;
        assert!(opening.await.unwrap().success);
        let scanning = {
            let bridge = bridge.clone();
            let env = env.clone();
            tokio::spawn(async move {
                WebScanTool::new(bridge)
                    .run(&json!({ "switch_tab_id": 33 }), &env)
                    .await
            })
        };
        reply_scan(
            &bridge,
            &mut rx,
            "https://robot.example",
            "Are you a robot?",
            captcha_text(),
        )
        .await;
        assert!(scanning.await.unwrap().success);

        let result = WebExecuteJsTool::new(bridge.clone(), store)
            .run(
                &json!({
                    "switch_tab_id": 33,
                    "script": "document.querySelector('button').click()"
                }),
                &env,
            )
            .await;
        assert!(!result.success);
        assert!(result.content.contains("human verification"));
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn confirm_needs_human_clears_when_challenge_is_gone() {
        let (store, tmp) = empty_store().await;
        let bridge = Arc::new(BrowserBridge::new_with_store(
            PathBuf::from("extension"),
            store.clone(),
        ));
        let (tx, mut rx) = mpsc::unbounded_channel();
        bridge.install_client(1, tx).await;
        let env = TurnEnv {
            root: PathBuf::from("."),
            turn_id: "turn-confirm".into(),
            frame_id: "frame-confirm".into(),
        };
        let opening = {
            let bridge = bridge.clone();
            let store = store.clone();
            let env = env.clone();
            tokio::spawn(async move {
                WebOpenTabTool::new(bridge, store)
                    .run(
                        &json!({ "url": "https://www.sciencedirect.com/science" }),
                        &env,
                    )
                    .await
            })
        };
        reply_open_tab(
            &bridge,
            &mut rx,
            44,
            "https://www.sciencedirect.com/science",
            "Just a moment...",
        )
        .await;
        assert!(opening.await.unwrap().success);
        let scanning = {
            let bridge = bridge.clone();
            let env = env.clone();
            tokio::spawn(async move {
                WebScanTool::new(bridge)
                    .run(&json!({ "switch_tab_id": 44 }), &env)
                    .await
            })
        };
        reply_scan(
            &bridge,
            &mut rx,
            "https://www.sciencedirect.com/science",
            "Just a moment...",
            captcha_text(),
        )
        .await;
        assert!(scanning.await.unwrap().success);

        let confirming = {
            let bridge = bridge.clone();
            tokio::spawn(async move { bridge.confirm_needs_human(&[]).await })
        };
        reply_scan(
            &bridge,
            &mut rx,
            "https://www.sciencedirect.com/science/article/pii/S000",
            "Article",
            "Abstract of the paper.",
        )
        .await;
        let result = confirming.await.unwrap().unwrap();
        assert!(result.still_required.is_empty());
        assert_eq!(result.cleared.len(), 1);
        assert!(bridge.list_needs_human().await.tabs.is_empty());
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn confirm_needs_human_keeps_waiting_when_challenge_remains() {
        let (store, tmp) = empty_store().await;
        let bridge = Arc::new(BrowserBridge::new_with_store(
            PathBuf::from("extension"),
            store.clone(),
        ));
        let (tx, mut rx) = mpsc::unbounded_channel();
        bridge.install_client(1, tx).await;
        let env = TurnEnv {
            root: PathBuf::from("."),
            turn_id: "turn-still".into(),
            frame_id: "frame-still".into(),
        };
        let opening = {
            let bridge = bridge.clone();
            let store = store.clone();
            let env = env.clone();
            tokio::spawn(async move {
                WebOpenTabTool::new(bridge, store)
                    .run(&json!({ "url": "https://robot.example" }), &env)
                    .await
            })
        };
        reply_open_tab(&bridge, &mut rx, 55, "https://robot.example", "Robot").await;
        assert!(opening.await.unwrap().success);
        let scanning = {
            let bridge = bridge.clone();
            let env = env.clone();
            tokio::spawn(async move {
                WebScanTool::new(bridge)
                    .run(&json!({ "switch_tab_id": 55 }), &env)
                    .await
            })
        };
        reply_scan(
            &bridge,
            &mut rx,
            "https://robot.example",
            "Are you a robot?",
            captcha_text(),
        )
        .await;
        assert!(scanning.await.unwrap().success);

        let confirming = {
            let bridge = bridge.clone();
            tokio::spawn(async move { bridge.confirm_needs_human(&[]).await })
        };
        reply_scan(
            &bridge,
            &mut rx,
            "https://robot.example",
            "Are you a robot?",
            captcha_text(),
        )
        .await;
        let result = confirming.await.unwrap().unwrap();
        assert_eq!(result.still_required.len(), 1);
        assert!(result.cleared.is_empty());
        assert_eq!(bridge.list_needs_human().await.tabs.len(), 1);
        let _ = std::fs::remove_file(tmp);
    }

    #[test]
    fn parse_created_tab_reads_id_from_tab_object_or_wrapper() {
        let direct =
            parse_created_tab(&json!({ "id": 7, "url": "https://a.example", "title": "A" }))
                .unwrap();
        assert_eq!(direct.id, 7);
        let wrapped = parse_created_tab(&json!({
            "tab": { "id": "8", "url": "https://b.example", "title": "B" }
        }))
        .unwrap();
        assert_eq!(wrapped.id, 8);
        assert!(parse_created_tab(&json!({ "url": "https://none.example" })).is_none());
    }

    // ---- Tab isolation (#1617) ----

    #[derive(Clone)]
    struct ScopedEnv {
        root: PathBuf,
        project_id: String,
        frame_id: String,
        turn_id: String,
        approve: bool,
        prompts: Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl ScopedEnv {
        fn new(project_id: &str, frame_id: &str, approve: bool) -> Self {
            Self {
                root: PathBuf::from("."),
                project_id: project_id.into(),
                frame_id: frame_id.into(),
                turn_id: format!("turn-{frame_id}"),
                approve,
                prompts: Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        fn prompts(&self) -> Vec<String> {
            self.prompts.lock().unwrap().clone()
        }

        fn scope(&self) -> ToolScope {
            ToolScope {
                lane: "shared".into(),
                project_id: self.project_id.clone(),
                frame_id: self.frame_id.clone(),
            }
        }
    }

    #[async_trait]
    impl ToolEnv for ScopedEnv {
        fn project_root(&self) -> &std::path::Path {
            &self.root
        }
        async fn confirm(&self, message: &str) -> bool {
            self.prompts.lock().unwrap().push(message.to_string());
            self.approve
        }
        async fn emit(&self, _event: wisp_tools::ToolEvent) {}
        fn project_id(&self) -> Option<&str> {
            Some(&self.project_id)
        }
        fn turn_id(&self) -> Option<&str> {
            Some(&self.turn_id)
        }
        fn frame_id(&self) -> Option<&str> {
            Some(&self.frame_id)
        }
    }

    fn page_tab(id: i64, url: &str, active: bool, window_id: i64) -> Value {
        json!({ "id": id, "url": url, "title": format!("Tab {id}"), "active": active, "windowId": window_id })
    }

    async fn handshake(
        bridge: &BrowserBridge,
        connection_id: u64,
        tabs: Vec<Value>,
        capabilities: &[&str],
        instance: &str,
    ) {
        bridge
            .handle_text(
                connection_id,
                &json!({
                    "type": "ext_ready",
                    "protocol_version": 2,
                    "extension_version": "0.4.3",
                    "capabilities": capabilities,
                    "browser_instance": instance,
                    "tabs": tabs
                })
                .to_string(),
            )
            .await;
    }

    /// The next request the bridge sent, plus its parsed JSON command (Null
    /// for plain JavaScript).
    async fn next_request(rx: &mut mpsc::UnboundedReceiver<Message>) -> (String, Value, Value) {
        let outbound = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("bridge should send a request")
            .unwrap()
            .into_text()
            .unwrap();
        let outbound: Value = serde_json::from_str(&outbound).unwrap();
        let command = outbound["code"]
            .as_str()
            .and_then(|code| serde_json::from_str::<Value>(code).ok())
            .unwrap_or(Value::Null);
        (
            outbound["id"].as_str().unwrap().to_string(),
            outbound,
            command,
        )
    }

    async fn reply(bridge: &BrowserBridge, connection_id: u64, id: &str, extra: Value) {
        let mut message = json!({ "type": "result", "id": id });
        for (key, value) in extra.as_object().unwrap() {
            message[key] = value.clone();
        }
        bridge
            .handle_text(connection_id, &message.to_string())
            .await;
    }

    /// Open a tab through web_open_tab as `env`, answering the extension with
    /// `created`. Returns the outbound tabs.create command and the result.
    async fn open_as(
        bridge: &Arc<BrowserBridge>,
        store: &Store,
        rx: &mut mpsc::UnboundedReceiver<Message>,
        env: &ScopedEnv,
        created: Value,
    ) -> (Value, ToolResult) {
        let running = {
            let bridge = bridge.clone();
            let store = store.clone();
            let env = env.clone();
            tokio::spawn(async move {
                WebOpenTabTool::new(bridge, store)
                    .run(&json!({ "url": "https://paper.example/" }), &env)
                    .await
            })
        };
        let (id, _, command) = next_request(rx).await;
        reply(bridge, 1, &id, json!({ "result": created })).await;
        (command, running.await.unwrap())
    }

    async fn scoped_bridge() -> (
        Arc<BrowserBridge>,
        Store,
        PathBuf,
        mpsc::UnboundedReceiver<Message>,
    ) {
        let (store, tmp) = empty_store().await;
        let bridge = Arc::new(BrowserBridge::new_with_store(
            PathBuf::from("extension"),
            store.clone(),
        ));
        let (tx, rx) = mpsc::unbounded_channel();
        bridge.install_client(1, tx).await;
        (bridge, store, tmp, rx)
    }

    fn listed_ids(content: &str) -> Vec<i64> {
        let body: Value = serde_json::from_str(content).unwrap();
        body["tabs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tab| tab["id"].as_i64().unwrap())
            .collect()
    }

    #[tokio::test]
    async fn tabs_only_and_explicit_ids_stay_inside_the_calling_conversation() {
        let (bridge, store, tmp, mut rx) = scoped_bridge().await;
        let user = page_tab(42, "https://mail.example", true, 1);
        handshake(&bridge, 1, vec![user.clone()], &[], "run-1").await;
        let a = ScopedEnv::new("proj", "frame-a", false);
        let b = ScopedEnv::new("proj", "frame-b", false);
        let a_tab = page_tab(50, "https://a.example", false, 1);
        let b_tab = page_tab(51, "https://b.example", false, 1);
        assert!(
            open_as(&bridge, &store, &mut rx, &a, a_tab.clone())
                .await
                .1
                .success
        );
        assert!(
            open_as(&bridge, &store, &mut rx, &b, b_tab.clone())
                .await
                .1
                .success
        );
        handshake(&bridge, 1, vec![user, a_tab, b_tab], &[], "run-1").await;

        let listed = WebScanTool::new(bridge.clone())
            .run(&json!({ "tabs_only": true }), &a)
            .await;
        assert!(listed.success, "{}", listed.content);
        assert_eq!(listed_ids(&listed.content), vec![50]);
        let body: Value = serde_json::from_str(&listed.content).unwrap();
        assert!(body["tab_isolation"]
            .as_str()
            .unwrap()
            .contains("not cookies or accounts"));

        let foreign = WebScanTool::new(bridge.clone())
            .run(&json!({ "switch_tab_id": 51 }), &a)
            .await;
        assert!(!foreign.success);
        assert!(
            foreign.content.contains("did not allow"),
            "{}",
            foreign.content
        );
        let prompts = a.prompts();
        assert_eq!(prompts.len(), 1);
        assert!(prompts[0].contains("#51"), "{}", prompts[0]);
        assert!(prompts[0].contains("Another conversation in this project"));
        assert!(
            rx.try_recv().is_err(),
            "a refused tab must never reach the extension"
        );

        // Hosts without a project and frame (CLI) keep seeing the whole lane.
        let cli = WebScanTool::new(bridge.clone())
            .run(&json!({ "tabs_only": true }), &NoEnv(PathBuf::from(".")))
            .await;
        assert_eq!(listed_ids(&cli.content), vec![42, 50, 51]);
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn another_project_gets_no_tabs_left_behind_by_a_finished_turn() {
        let (bridge, store, tmp, mut rx) = scoped_bridge().await;
        handshake(&bridge, 1, Vec::new(), &[], "run-1").await;
        let a = ScopedEnv::new("proj-a", "frame-a", false);
        let a_tab = page_tab(50, "https://a.example", true, 1);
        assert!(
            open_as(&bridge, &store, &mut rx, &a, a_tab.clone())
                .await
                .1
                .success
        );
        handshake(&bridge, 1, vec![a_tab], &[], "run-1").await;
        let _ = bridge.complete_turn(&a.turn_id).await;

        let b = ScopedEnv::new("proj-b", "frame-b", false);
        let scan = WebScanTool::new(bridge.clone()).run(&json!({}), &b).await;
        assert!(!scan.success);
        assert!(
            scan.content.contains("no browser tab yet"),
            "{}",
            scan.content
        );
        let explicit = WebScanTool::new(bridge.clone())
            .run(&json!({ "switch_tab_id": 50 }), &b)
            .await;
        assert!(!explicit.success);
        assert!(b.prompts()[0].contains("Another project's conversation"));
        assert!(rx.try_recv().is_err());
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn the_default_tab_never_falls_back_to_the_users_active_tab() {
        let (bridge, store, tmp, mut rx) = scoped_bridge().await;
        let user = page_tab(42, "https://mail.example", true, 1);
        handshake(&bridge, 1, vec![user.clone()], &[], "run-1").await;
        let a = ScopedEnv::new("proj", "frame-a", true);

        let empty = WebScanTool::new(bridge.clone()).run(&json!({}), &a).await;
        assert!(!empty.success);
        assert!(empty.content.contains("web_open_tab"), "{}", empty.content);
        assert!(
            a.prompts().is_empty(),
            "the default must not ask for the user's tab"
        );
        assert!(rx.try_recv().is_err());

        let own = page_tab(60, "https://paper.example", false, 1);
        assert!(
            open_as(&bridge, &store, &mut rx, &a, own.clone())
                .await
                .1
                .success
        );
        handshake(&bridge, 1, vec![user, own], &[], "run-1").await;
        let scanning = {
            let bridge = bridge.clone();
            let a = a.clone();
            tokio::spawn(async move { WebScanTool::new(bridge).run(&json!({}), &a).await })
        };
        let (id, outbound, _) = next_request(&mut rx).await;
        assert_eq!(outbound["tabId"], 60);
        reply(
            &bridge,
            1,
            &id,
            json!({ "result": { "url": "https://paper.example", "title": "P", "text": "" } }),
        )
        .await;
        assert!(scanning.await.unwrap().success);
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn approving_the_grant_prompt_adopts_the_tab() {
        let (bridge, _store, tmp, mut rx) = scoped_bridge().await;
        handshake(
            &bridge,
            1,
            vec![page_tab(42, "https://mail.example/inbox", true, 1)],
            &[],
            "run-1",
        )
        .await;
        let a = ScopedEnv::new("proj", "frame-a", true);

        let scanning = {
            let bridge = bridge.clone();
            let a = a.clone();
            tokio::spawn(async move {
                WebScanTool::new(bridge)
                    .run(&json!({ "switch_tab_id": "active" }), &a)
                    .await
            })
        };
        let (id, outbound, _) = next_request(&mut rx).await;
        assert_eq!(outbound["tabId"], 42);
        reply(
            &bridge,
            1,
            &id,
            json!({ "result": { "url": "https://mail.example/inbox", "title": "Inbox", "text": "" } }),
        )
        .await;
        assert!(scanning.await.unwrap().success);
        let prompts = a.prompts();
        assert_eq!(prompts.len(), 1);
        assert!(
            prompts[0].contains("#42: Tab 42 (https://mail.example/inbox)"),
            "{}",
            prompts[0]
        );

        // Granted once, the tab is in scope without asking again.
        let listed = WebScanTool::new(bridge.clone())
            .run(&json!({ "tabs_only": true }), &a)
            .await;
        assert_eq!(listed_ids(&listed.content), vec![42]);
        assert_eq!(a.prompts().len(), 1);

        // Another conversation is asked separately and can be refused.
        let b = ScopedEnv::new("proj", "frame-b", false);
        let refused = WebScanTool::new(bridge.clone())
            .run(&json!({ "switch_tab_id": 42 }), &b)
            .await;
        assert!(!refused.success);
        assert!(refused.content.contains("did not allow"));
        assert!(rx.try_recv().is_err());
        let still_a = WebScanTool::new(bridge.clone())
            .run(&json!({ "tabs_only": true }), &a)
            .await;
        assert_eq!(
            listed_ids(&still_a.content),
            vec![42],
            "a refusal must not move the tab"
        );
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn embedded_tab_references_outside_the_scope_are_refused() {
        let (bridge, store, tmp, mut rx) = scoped_bridge().await;
        let user = page_tab(42, "https://mail.example", true, 1);
        handshake(&bridge, 1, vec![user.clone()], &[], "run-1").await;
        let a = ScopedEnv::new("proj", "frame-a", true);
        let own = page_tab(50, "https://a.example", false, 1);
        assert!(
            open_as(&bridge, &store, &mut rx, &a, own.clone())
                .await
                .1
                .success
        );
        handshake(&bridge, 1, vec![user, own], &[], "run-1").await;
        for script in [
            r#"{"cmd":"tabs","method":"close","tabIds":[42]}"#,
            r#"{"cmd":"tabs","method":"close","tabIds":[50, 42.0]}"#,
            r#"{"cmd":"tabs","method":"close","tabId":42}"#,
            r#"{"cmd":"tabs","method":"close","tabIds":42}"#,
            r#"{"cmd":"tabs","method":"switch","tabId":42}"#,
            r#"{"cmd":"cdp","tabId":42,"method":"Page.reload"}"#,
            r#"{"cmd":"cdp","tabId":"42","method":"Page.reload"}"#,
            r#"{"cmd":"cdp","method":"Target.createTarget","params":{"url":"https://x.example"}}"#,
            r#"{"cmd":"cdp","method":"Target.attachToTarget","params":{"targetId":"t"}}"#,
            r#"{"cmd":"cdp","method":"Browser.close"}"#,
            r#"{"cmd":"cdp","method":"Target.createTarget","x":"\ud800"}"#,
        ] {
            let result = WebExecuteJsTool::new(bridge.clone(), store.clone())
                .run(&json!({ "switch_tab_id": 50, "script": script }), &a)
                .await;
            assert!(!result.success, "{script} should be refused");
            assert!(
                rx.try_recv().is_err(),
                "{script} must not reach the extension"
            );
        }
        assert!(
            a.prompts().is_empty(),
            "embedded ids are refused, not offered for approval"
        );
        assert_eq!(
            scoped_tab_refs("document.title").unwrap(),
            Vec::<i64>::new()
        );
        assert_eq!(
            scoped_tab_refs(r#"{"cmd":"tabs","method":"close","tabIds":[50,"42",7.5]}"#).unwrap(),
            vec![50]
        );
        assert_eq!(
            scoped_tab_refs(r#"{"cmd":"cdp","tabId":0,"method":"Page.reload"}"#).unwrap(),
            Vec::<i64>::new()
        );
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn tab_lists_and_close_remaining_are_filtered_to_the_scope() {
        let (bridge, store, tmp, mut rx) = scoped_bridge().await;
        let user = page_tab(42, "https://mail.example", true, 1);
        let kept = page_tab(50, "https://a.example", false, 1);
        let closing_tab = page_tab(52, "https://c.example", false, 1);
        handshake(&bridge, 1, vec![user.clone()], &[], "run-1").await;
        let a = ScopedEnv::new("proj", "frame-a", true);
        assert!(
            open_as(&bridge, &store, &mut rx, &a, kept.clone())
                .await
                .1
                .success
        );
        assert!(
            open_as(&bridge, &store, &mut rx, &a, closing_tab.clone())
                .await
                .1
                .success
        );
        handshake(
            &bridge,
            1,
            vec![user.clone(), kept.clone(), closing_tab],
            &[],
            "run-1",
        )
        .await;

        let closing = {
            let bridge = bridge.clone();
            let store = store.clone();
            let a = a.clone();
            tokio::spawn(async move {
                WebExecuteJsTool::new(bridge, store)
                    .run(
                        &json!({ "switch_tab_id": 50, "script": r#"{"cmd":"tabs","method":"close","tabIds":[52]}"# }),
                        &a,
                    )
                    .await
            })
        };
        let (id, _, command) = next_request(&mut rx).await;
        assert_eq!(command["tabIds"], json!([52]));
        reply(
            &bridge,
            1,
            &id,
            json!({ "result": { "closed": [52], "remaining": [user.clone(), kept.clone()] } }),
        )
        .await;
        let closed = closing.await.unwrap();
        assert!(closed.success, "{}", closed.content);
        let body: Value = serde_json::from_str(&closed.content).unwrap();
        assert_eq!(body["result"]["remaining"], json!([kept.clone()]));

        let listing = {
            let bridge = bridge.clone();
            let store = store.clone();
            let a = a.clone();
            tokio::spawn(async move {
                WebExecuteJsTool::new(bridge, store)
                    .run(
                        &json!({ "switch_tab_id": 50, "script": r#"{"cmd":"tabs"}"# }),
                        &a,
                    )
                    .await
            })
        };
        let (id, _, _) = next_request(&mut rx).await;
        reply(&bridge, 1, &id, json!({ "result": [user, kept.clone()] })).await;
        let listed: Value = serde_json::from_str(&listing.await.unwrap().content).unwrap();
        assert_eq!(listed["result"], json!([kept]));
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn only_popups_opened_by_the_operated_tab_join_the_scope() {
        let (bridge, store, tmp, mut rx) = scoped_bridge().await;
        handshake(&bridge, 1, Vec::new(), &[], "run-1").await;
        let a = ScopedEnv::new("proj", "frame-a", false);
        let own = page_tab(50, "https://a.example", false, 1);
        assert!(
            open_as(&bridge, &store, &mut rx, &a, own.clone())
                .await
                .1
                .success
        );
        handshake(&bridge, 1, vec![own.clone()], &[], "run-1").await;

        let clicking = {
            let bridge = bridge.clone();
            let store = store.clone();
            let a = a.clone();
            tokio::spawn(async move {
                WebExecuteJsTool::new(bridge, store)
                    .run(
                        &json!({ "switch_tab_id": 50, "script": "document.querySelector('a').click()" }),
                        &a,
                    )
                    .await
            })
        };
        let (id, _, _) = next_request(&mut rx).await;
        reply(
            &bridge,
            1,
            &id,
            json!({
                "result": null,
                "newTabs": [
                    { "id": 70, "url": "https://popup.example", "openerTabId": 50 },
                    { "id": 71, "url": "https://user.example", "openerTabId": 42 },
                    { "id": 72, "url": "https://other.example" }
                ]
            }),
        )
        .await;
        let clicked = clicking.await.unwrap();
        assert!(clicked.success, "{}", clicked.content);
        let body: Value = serde_json::from_str(&clicked.content).unwrap();
        assert_eq!(body["new_tabs"], json!([70]));

        handshake(
            &bridge,
            1,
            vec![
                own,
                page_tab(70, "https://popup.example", true, 1),
                page_tab(71, "https://user.example", false, 1),
                page_tab(72, "https://other.example", false, 1),
            ],
            &[],
            "run-1",
        )
        .await;
        let listed = WebScanTool::new(bridge.clone())
            .run(&json!({ "tabs_only": true }), &a)
            .await;
        assert_eq!(listed_ids(&listed.content), vec![50, 70]);
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn new_tabs_open_in_one_bound_window_per_project() {
        let (bridge, store, tmp, mut rx) = scoped_bridge().await;
        handshake(&bridge, 1, Vec::new(), &["window_binding"], "run-1").await;
        let a = ScopedEnv::new("proj", "frame-a", false);
        let (first, opened) = open_as(
            &bridge,
            &store,
            &mut rx,
            &a,
            page_tab(80, "https://a.example", false, 5),
        )
        .await;
        assert!(opened.success, "{}", opened.content);
        assert_eq!(first["newWindow"], true);
        assert!(first.get("windowId").is_none());
        assert!(!opened.content.contains("window_note"));

        let (second, _) = open_as(
            &bridge,
            &store,
            &mut rx,
            &a,
            page_tab(81, "https://b.example", false, 5),
        )
        .await;
        assert_eq!(second["windowId"], 5);
        assert!(second.get("newWindow").is_none());

        // Another conversation in the same project shares the project window.
        let b = ScopedEnv::new("proj", "frame-b", false);
        let (sibling, _) = open_as(
            &bridge,
            &store,
            &mut rx,
            &b,
            page_tab(82, "https://c.example", false, 5),
        )
        .await;
        assert_eq!(sibling["windowId"], 5);
        let _ = bridge.complete_turn(&a.turn_id).await;
        let _ = bridge.complete_turn(&b.turn_id).await;

        // A different project gets its own window.
        let c = ScopedEnv::new("proj-c", "frame-c", false);
        let (foreign, _) = open_as(
            &bridge,
            &store,
            &mut rx,
            &c,
            page_tab(83, "https://d.example", false, 6),
        )
        .await;
        assert_eq!(foreign["newWindow"], true);
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn a_closed_project_window_is_rebuilt_and_rebound() {
        let (bridge, store, tmp, mut rx) = scoped_bridge().await;
        handshake(&bridge, 1, Vec::new(), &["window_binding"], "run-1").await;
        let a = ScopedEnv::new("proj", "frame-a", false);
        open_as(
            &bridge,
            &store,
            &mut rx,
            &a,
            page_tab(80, "https://a.example", false, 5),
        )
        .await;

        let opening = {
            let bridge = bridge.clone();
            let store = store.clone();
            let a = a.clone();
            tokio::spawn(async move {
                WebOpenTabTool::new(bridge, store)
                    .run(&json!({ "url": "https://paper.example/2" }), &a)
                    .await
            })
        };
        let (id, _, command) = next_request(&mut rx).await;
        assert_eq!(command["windowId"], 5);
        bridge
            .handle_text(
                1,
                &json!({
                    "type": "error",
                    "id": id,
                    "error": { "code": "window_gone", "message": "window_gone: bound window 5 is no longer open", "retryable": false }
                })
                .to_string(),
            )
            .await;
        let (id, _, retry) = next_request(&mut rx).await;
        assert_eq!(retry["newWindow"], true);
        assert!(
            retry.get("windowId").is_none(),
            "never reuse the dead window id"
        );
        reply(
            &bridge,
            1,
            &id,
            json!({ "result": page_tab(84, "https://paper.example/2", false, 9) }),
        )
        .await;
        let opened = opening.await.unwrap();
        assert!(opened.success, "{}", opened.content);
        assert!(
            opened.content.contains("window was closed"),
            "{}",
            opened.content
        );

        let (next, _) = open_as(
            &bridge,
            &store,
            &mut rx,
            &a,
            page_tab(85, "https://c.example", false, 9),
        )
        .await;
        assert_eq!(next["windowId"], 9);
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn an_extension_without_window_binding_says_the_fixed_window_is_unavailable() {
        let (bridge, store, tmp, mut rx) = scoped_bridge().await;
        handshake(&bridge, 1, Vec::new(), &["article_scan"], "").await;
        let a = ScopedEnv::new("proj", "frame-a", false);
        let (command, opened) = open_as(
            &bridge,
            &store,
            &mut rx,
            &a,
            page_tab(80, "https://a.example", false, 5),
        )
        .await;
        assert!(opened.success);
        assert!(command.get("windowId").is_none());
        assert!(command.get("newWindow").is_none());
        assert!(
            opened.content.contains("Fixed project window unavailable"),
            "{}",
            opened.content
        );
        assert!(opened.content.contains("update_extension"));
        // Ownership is enforced bridge-side regardless of the extension.
        handshake(
            &bridge,
            1,
            vec![page_tab(80, "https://a.example", false, 5)],
            &["article_scan"],
            "",
        )
        .await;
        let mine = WebScanTool::new(bridge.clone())
            .run(&json!({ "tabs_only": true }), &a)
            .await;
        assert_eq!(listed_ids(&mine.content), vec![80]);
        let sibling = WebScanTool::new(bridge.clone())
            .run(
                &json!({ "tabs_only": true }),
                &ScopedEnv::new("proj", "frame-b", false),
            )
            .await;
        assert!(listed_ids(&sibling.content).is_empty());
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn a_new_browser_run_drops_ownership_but_a_worker_restart_keeps_it() {
        let (bridge, store, tmp, mut rx) = scoped_bridge().await;
        handshake(&bridge, 1, Vec::new(), &["window_binding"], "run-1").await;
        let a = ScopedEnv::new("proj", "frame-a", false);
        open_as(
            &bridge,
            &store,
            &mut rx,
            &a,
            page_tab(50, "https://a.example", false, 5),
        )
        .await;
        let owns = |bridge: Arc<BrowserBridge>, id: i64| async move {
            bridge.state.lock().await.sessions["shared"]
                .owners
                .contains_key(&id)
        };

        // Service worker restart: same run id, ownership and window survive.
        let (tx, _rx2) = mpsc::unbounded_channel();
        bridge.install_client(2, tx).await;
        handshake(
            &bridge,
            2,
            vec![page_tab(50, "https://a.example", false, 5)],
            &["window_binding"],
            "run-1",
        )
        .await;
        assert!(owns(bridge.clone(), 50).await);
        assert_eq!(
            bridge.state.lock().await.sessions["shared"]
                .project_windows
                .get("proj"),
            Some(&5)
        );

        // Browser restart: tab and window ids start over, so nothing carries.
        let (tx, _rx3) = mpsc::unbounded_channel();
        bridge.install_client(3, tx).await;
        handshake(
            &bridge,
            3,
            vec![page_tab(50, "https://new-run.example", false, 1)],
            &["window_binding"],
            "run-2",
        )
        .await;
        assert!(!owns(bridge.clone(), 50).await);
        assert!(bridge.state.lock().await.sessions["shared"]
            .project_windows
            .is_empty());

        // Later handshakes on the same connection do not clear again.
        bridge
            .adopt_created_tab(
                "shared",
                &a.scope(),
                &page_tab(90, "https://a.example", false, 1),
            )
            .await;
        handshake(
            &bridge,
            3,
            vec![page_tab(90, "https://a.example", false, 1)],
            &["window_binding"],
            "run-2",
        )
        .await;
        assert!(owns(bridge.clone(), 90).await);

        // An extension without a run id drops ownership on every reconnect.
        let (tx, _rx4) = mpsc::unbounded_channel();
        bridge.install_client(4, tx).await;
        handshake(
            &bridge,
            4,
            vec![page_tab(90, "https://a.example", false, 1)],
            &[],
            "",
        )
        .await;
        assert!(!owns(bridge.clone(), 90).await);
        let _ = std::fs::remove_file(tmp);
    }

    #[tokio::test]
    async fn needs_human_commands_act_only_on_the_windows_project() {
        let (store, tmp) = empty_store().await;
        for id in ["a", "b"] {
            store
                .create_project(id, id, &format!("/ws/{id}"))
                .await
                .unwrap();
            store
                .create_frame(&format!("frame-{id}"), id, "OPERON", "model")
                .await
                .unwrap();
        }
        let bridge = Arc::new(BrowserBridge::new_with_store(
            PathBuf::from("extension"),
            store.clone(),
        ));
        let (tx, mut rx) = mpsc::unbounded_channel();
        bridge.install_client(1, tx).await;
        handshake(
            &bridge,
            1,
            vec![
                page_tab(11, "https://a.example", false, 1),
                page_tab(12, "https://b.example", false, 1),
            ],
            &[],
            "run-1",
        )
        .await;
        for (tab_id, frame) in [(11, "frame-a"), (12, "frame-b")] {
            bridge.needs_human.lock().await.insert(
                ("shared".into(), tab_id),
                BrowserNeedsHumanTab {
                    session: "shared".into(),
                    tab_id,
                    frame_id: frame.into(),
                    ..Default::default()
                },
            );
        }

        let error = bridge
            .focus_needs_human_for_project(&store, Some("a"), "shared", 12)
            .await
            .unwrap_err();
        assert!(error.contains("not waiting for verification in this project"));
        assert!(bridge
            .focus_needs_human_for_project(&store, Some("a"), "shared", 42)
            .await
            .is_err());
        assert!(rx.try_recv().is_err());

        let focusing = {
            let bridge = bridge.clone();
            let store = store.clone();
            tokio::spawn(async move {
                bridge
                    .focus_needs_human_for_project(&store, Some("a"), "shared", 11)
                    .await
            })
        };
        let (id, _, command) = next_request(&mut rx).await;
        assert_eq!(command["method"], "switch");
        assert_eq!(command["tabId"], 11);
        reply(&bridge, 1, &id, json!({ "result": { "ok": true } })).await;
        focusing.await.unwrap().unwrap();

        // A frame id forged by the caller does not make b's tab confirmable.
        let forged = BrowserNeedsHumanTab {
            session: "shared".into(),
            tab_id: 12,
            frame_id: "frame-a".into(),
            ..Default::default()
        };
        let result = bridge
            .confirm_needs_human_for_project(&store, Some("a"), &[forged])
            .await
            .unwrap();
        assert!(result.cleared.is_empty() && result.still_required.is_empty());
        assert!(
            rx.try_recv().is_err(),
            "nothing may be scanned for another project"
        );
        let unbound = bridge
            .confirm_needs_human_for_project(&store, None, &[])
            .await
            .unwrap();
        assert!(unbound.cleared.is_empty() && unbound.still_required.is_empty());
        assert!(rx.try_recv().is_err());

        let confirming = {
            let bridge = bridge.clone();
            let store = store.clone();
            tokio::spawn(async move {
                bridge
                    .confirm_needs_human_for_project(&store, Some("a"), &[])
                    .await
            })
        };
        let (id, outbound, _) = next_request(&mut rx).await;
        assert_eq!(outbound["tabId"], 11);
        reply(
            &bridge,
            1,
            &id,
            json!({ "result": { "url": "https://a.example", "title": "A", "text": "ok" } }),
        )
        .await;
        let confirmed = confirming.await.unwrap().unwrap();
        assert_eq!(confirmed.cleared.len(), 1);
        assert_eq!(confirmed.cleared[0].tab_id, 11);
        assert_eq!(bridge.snapshot_needs_human().await[0].tab_id, 12);
        drop(store);
        let _ = std::fs::remove_file(tmp);
    }

    #[test]
    fn select_tab_defaults_inside_the_scope_and_unscoped_keeps_the_old_order() {
        let mut slot = SessionState::default();
        for (id, active) in [(1, true), (2, false), (3, false)] {
            slot.tabs.insert(id, tab(id, "https://example.com", active));
        }
        let scope = ToolScope {
            lane: "shared".into(),
            project_id: "p".into(),
            frame_id: "f".into(),
        };
        assert!(select_tab(&slot, None, Some(&scope))
            .unwrap_err()
            .contains("no browser tab yet"));
        assert_eq!(select_tab(&slot, None, None).unwrap(), 1);
        slot.owners.insert(3, scope.owner());
        slot.owners.insert(
            2,
            TabOwner {
                project_id: "p".into(),
                frame_id: "other".into(),
            },
        );
        assert_eq!(select_tab(&slot, None, Some(&scope)).unwrap(), 3);
        assert!(select_tab(&slot, Some(2), Some(&scope))
            .unwrap_err()
            .contains("not shared with this conversation"));
        assert!(select_tab(&slot, Some(9), Some(&scope))
            .unwrap_err()
            .contains("not available"));
        // Selection is remembered per conversation frame.
        slot.selected_by_frame.insert("other".into(), 2);
        assert_eq!(select_tab(&slot, None, Some(&scope)).unwrap(), 3);
    }
}
