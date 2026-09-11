//! Commands for the isolated MCP App shell.
//!
//! The primary document owns layout and user-facing lifecycle.  The child
//! document owns only the JSON-RPC-shaped guest protocol.  Keeping these
//! commands separate is intentional: a child WebView must not become a second
//! general-purpose workspace client just because it shares a native window.

use std::time::Duration;

use serde_json::{json, Value};
use tauri::{AppHandle, Manager, State, Webview};

use wisp_dto::{
    McpAppChildBootstrap, McpAppChildBounds, McpAppChildCloseReason, McpAppChildDelivery,
    McpAppChildHandle, McpAppChildRequest, McpAppHostInfo,
};

use crate::{
    app_state::{mcp_app_frame_id, AppState},
    mcp_app_children::{self, Child, McpAppChildren, Retirement, STALE},
    workspace_surface::WorkspaceSurface,
};

fn jsonrpc_error(id: Option<Value>, message: impl Into<String>) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32603, "message": message.into() } })
}

fn jsonrpc_result(id: Option<Value>, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn verify_owner(
    state: &AppState,
    owner: &WorkspaceSurface,
    instance_id: &str,
) -> Result<(), String> {
    let frame = mcp_app_frame_id(instance_id)?;
    if state.active_frame(owner.label()).as_deref() != Some(frame) {
        return Err(STALE.into());
    }
    Ok(())
}

fn finish_retirement(app: &AppHandle, retired: Retirement) {
    // Releases are generation-fenced. A replacement with the same instance id
    // must never have its newly registered bridge revoked by this cleanup.
    for (instance, generation) in retired.releases {
        // During the initial page load AppState may not exist yet.
        let Some(state) = app.try_state::<AppState>() else {
            continue;
        };
        // A reopen can race the native retirement queue. Check the logical
        // reference count again while closing only the observed generation.
        {
            let Some(children) = app.try_state::<McpAppChildren>() else {
                continue;
            };
            let registry = children.registry.lock().unwrap();
            if !registry.has_binding(&instance) {
                state
                    .mcp_app_tool_bridges
                    .close_generation(&instance, generation);
            }
        }
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            let Some(state) = app.try_state::<AppState>() else {
                return;
            };
            let sessions = state.sessions.lock().await;
            let Some(children) = app.try_state::<McpAppChildren>() else {
                return;
            };
            let registry = children.registry.lock().unwrap();
            if !registry.has_binding(&instance) && state.mcp_app_bridge(&instance).is_none() {
                if let Ok(frame) = mcp_app_frame_id(&instance) {
                    if let Some(runtime) = sessions.get(frame) {
                        runtime.set_mcp_app_context(instance.clone(), None);
                    }
                }
            }
        });
    }
    mcp_app_children::retire_native(app, retired.children);
}

pub(crate) fn ensure_current(state: &AppState, child: &Child) -> Result<(), String> {
    child.ensure_live()?;
    if state.active_frame(&child.owner).as_deref() != Some(mcp_app_frame_id(&child.instance_id)?) {
        return Err(STALE.into());
    }
    let current = state.mcp_app_bridge(&child.instance_id);
    if child.bridge_generation.is_some()
        && current.as_ref().map(|b| b.generation) != child.bridge_generation
    {
        return Err(STALE.into());
    }
    Ok(())
}

pub(crate) fn suspend_owner(app: &AppHandle, owner: &str) {
    let Some(state) = app.try_state::<McpAppChildren>() else {
        return;
    };
    let retired = {
        let mut registry = state.registry.lock().unwrap();
        registry.suspend_owner(owner)
    };
    finish_retirement(app, retired);
}

pub(crate) fn reset_owner(app: &AppHandle, owner: &str, destroy: bool) {
    let Some(state) = app.try_state::<McpAppChildren>() else {
        return;
    };
    let retirement = {
        let mut registry = state.registry.lock().unwrap();
        registry.reset_owner(owner, destroy)
    };
    finish_retirement(app, retirement);
}

pub(crate) fn remove_frame(app: &AppHandle, frame: &str) {
    let Some(state) = app.try_state::<McpAppChildren>() else {
        return;
    };
    let retirement = {
        let mut registry = state.registry.lock().unwrap();
        registry.remove_frame(&format!("mcp-app:{frame}:"))
    };
    finish_retirement(app, retirement);
}

#[tauri::command]
pub(crate) fn mcp_app_host_info(window: WorkspaceSurface) -> Result<McpAppHostInfo, String> {
    let app = window.app_handle();
    let state = app.state::<McpAppChildren>();
    let owner_epoch = state.registry.lock().unwrap().epoch(window.label());
    Ok(McpAppHostInfo {
        backend: if cfg!(windows) {
            "native-child"
        } else {
            "legacy-iframe"
        }
        .into(),
        owner_epoch,
    })
}

#[tauri::command]
pub(crate) async fn open_mcp_app_child(
    app: AppHandle,
    window: WorkspaceSurface,
    state: State<'_, AppState>,
    instance_id: String,
    payload: Value,
    host_context: Value,
    bounds: McpAppChildBounds,
    owner_epoch: String,
    mount_serial: u64,
) -> Result<McpAppChildHandle, String> {
    verify_owner(&state, &window, &instance_id)?;
    // Only a primary workspace can request a fresh binding; old child RPCs cannot.
    let payload = if state
        .mcp_app_bridge(&instance_id)
        .is_some_and(|b| b.server.is_connected())
    {
        payload
    } else {
        crate::mcp_connections::restore_app(&state, &instance_id)
            .await?
            .unwrap_or(payload)
    };
    verify_owner(&state, &window, &instance_id)?;
    let frame = mcp_app_frame_id(&instance_id)?;
    if crate::mcp_app_instance_id(frame, &payload) != instance_id {
        return Err("MCP App presentation identity does not match the Tab".into());
    }
    if payload
        .pointer("/resource/text")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
        || serde_json::to_vec(&payload)
            .map_err(|e| e.to_string())?
            .len()
            > 32 * 1024 * 1024
        || serde_json::to_vec(&host_context)
            .map_err(|e| e.to_string())?
            .len()
            > 64 * 1024
    {
        return Err("Invalid or oversized MCP App presentation/context".into());
    }
    let (child, retired) = {
        let children = app.state::<McpAppChildren>();
        let mut registry = children.registry.lock().unwrap();
        // Do not read active_frame while holding the registry: session switches
        // update the frame first, then suspend. Recheck after native create.
        let generation = state.mcp_app_bridge(&instance_id).map(|b| b.generation);
        if owner_epoch != registry.epoch(window.label()) {
            return Err(STALE.into());
        }
        registry.reserve(
            window.label(),
            &owner_epoch,
            mount_serial,
            &instance_id,
            payload,
            host_context,
            bounds,
            generation,
        )?
    };
    finish_retirement(&app, retired);
    let created = async {
        mcp_app_children::create_native(&app, &window, &child).await?;
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                ensure_current(&state, &child)?;
                if app
                    .state::<McpAppChildren>()
                    .registry
                    .lock()
                    .unwrap()
                    .get(&child.handle.child_label)?
                    .ready
                {
                    return Ok::<_, String>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .map_err(|_| "MCP App shell did not become ready; close or retry this view".to_string())?
    }
    .await;
    if let Err(error) = created {
        let retired = {
            let children = app.state::<McpAppChildren>();
            let mut registry = children.registry.lock().unwrap();
            registry.close(
                window.label(),
                &child.handle.owner_epoch,
                child.handle.mount_serial,
                &child.instance_id,
                McpAppChildCloseReason::Replace,
            )
        };
        finish_retirement(&app, retired);
        return Err(error);
    }
    if verify_owner(&state, &window, &instance_id).is_err() {
        suspend_owner(&app, window.label());
        return Err(STALE.into());
    }
    child.ensure_live()?;
    Ok(child.handle)
}

#[tauri::command]
pub(crate) async fn update_mcp_app_child_bounds(
    window: WorkspaceSurface,
    app: AppHandle,
    state: State<'_, AppState>,
    handle: McpAppChildHandle,
    bounds: McpAppChildBounds,
    host_context: Value,
) -> Result<bool, String> {
    let children = app.state::<McpAppChildren>();
    let _native = children.native_ops.lock().await;
    let child = app
        .state::<McpAppChildren>()
        .registry
        .lock()
        .unwrap()
        .get(&handle.child_label)?;
    verify_owner(&state, &window, &child.instance_id)?;
    if serde_json::to_vec(&host_context)
        .map_err(|e| e.to_string())?
        .len()
        > 64 * 1024
    {
        return Err("Oversized host context".into());
    }
    if !bounds.visible {
        window.focus_document().map_err(|e| e.to_string())?;
    }
    mcp_app_children::update_geometry(&app, window.label(), &handle, bounds, host_context)
}

#[tauri::command]
pub(crate) fn mcp_app_child_bootstrap(
    webview: Webview,
    app: AppHandle,
) -> Result<McpAppChildBootstrap, String> {
    let child = mcp_app_children::caller_child(&app, &webview)?;
    ensure_current(&app.state::<AppState>(), &child)?;
    Ok(McpAppChildBootstrap {
        server_tools_available: app
            .state::<AppState>()
            .mcp_app_bridge(&child.instance_id)
            .is_some_and(|b| {
                Some(b.generation) == child.bridge_generation && b.server.is_connected()
            }),
        handle: child.handle,
        instance_id: child.instance_id,
        payload: (*child.payload).clone(),
        host_context: child.host_context,
        version: env!("CARGO_PKG_VERSION").into(),
    })
}

#[tauri::command]
pub(crate) async fn mcp_app_child_ready(webview: Webview, app: AppHandle) -> Result<(), String> {
    let children = app.state::<McpAppChildren>();
    let _native = children.native_ops.lock().await;
    let child = mcp_app_children::caller_child(&app, &webview)?;
    mcp_app_children::set_ready(&app, &child.handle.child_label)?;
    Ok(())
}

#[tauri::command]
pub(crate) async fn mcp_app_child_request(
    webview: Webview,
    app: AppHandle,
    state: State<'_, AppState>,
    request: McpAppChildRequest,
) -> Result<Value, String> {
    let child = mcp_app_children::caller_child(&app, &webview)?;
    ensure_current(&state, &child)?;
    if request.method.len() > 128
        || request.id.as_ref().is_some_and(|id| {
            !id.is_null() && !id.is_number() && !id.as_str().is_some_and(|s| s.len() <= 256)
        })
        || serde_json::to_vec(&request.params)
            .map_err(|e| e.to_string())?
            .len()
            > crate::MAX_MCP_APP_ARGUMENT_BYTES
    {
        return Err("Invalid or oversized MCP App request".into());
    }
    let id = request.id.clone();
    let result = match request.method.as_str() {
        "ping" => json!({}),
        "ui/initialize" => {
            let csp = child
                .payload
                .pointer("/resource/_meta/ui/csp")
                .or_else(|| child.payload.pointer("/resource/_meta/csp"))
                .cloned()
                .unwrap_or_else(|| json!({}));
            let mut capabilities =
                json!({ "sandbox": { "csp": csp }, "updateModelContext": { "text": {} } });
            if state.mcp_app_bridge(&child.instance_id).is_some_and(|b| {
                Some(b.generation) == child.bridge_generation && b.server.is_connected()
            }) {
                capabilities["serverTools"] = json!({});
            }
            json!({ "protocolVersion": request.params.get("protocolVersion").and_then(Value::as_str).unwrap_or("2026-01-26"), "hostCapabilities": capabilities, "hostContext": child.host_context, "hostInfo": { "name": "wisp-science", "version": env!("CARGO_PKG_VERSION") } })
        }
        "tools/list" => {
            let bridge = state.mcp_app_bridge(&child.instance_id).ok_or(STALE)?;
            if Some(bridge.generation) != child.bridge_generation || !bridge.server.is_connected() {
                return Err(crate::MCP_APP_STALE_INSTANCE_ERROR.into());
            }
            json!({ "tools": bridge.server.tools().into_iter().filter(|tool| tool.get("name").and_then(Value::as_str).is_some_and(|name| bridge.server.visible_to_app(name))).collect::<Vec<_>>() })
        }
        "tools/call" => {
            let params = request
                .params
                .as_object()
                .ok_or("tools/call params must be an object")?;
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .ok_or("tools/call requires a name")?
                .to_string();
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            crate::call_mcp_app_tool_inner(
                app.clone(),
                &state,
                child.instance_id.clone(),
                name,
                arguments,
                Some(&child),
            )
            .await?
        }
        "ui/update-model-context" => {
            let title = child
                .payload
                .pointer("/tool/title")
                .or_else(|| child.payload.pointer("/tool/name"))
                .and_then(Value::as_str)
                .unwrap_or("MCP App");
            let context = crate::normalize_mcp_app_context(title, request.params)?;
            let frame = mcp_app_frame_id(&child.instance_id)?.to_string();
            if state
                .store
                .frame_project_id(&frame)
                .await
                .map_err(|e| e.to_string())?
                .is_none()
            {
                return Err(STALE.into());
            }
            let mut sessions = state.sessions.lock().await;
            ensure_current(&state, &child)?;
            let runtime = sessions
                .entry(frame)
                .or_insert_with(|| std::sync::Arc::new(crate::SessionRuntime::new()));
            if runtime.deleted.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(STALE.into());
            }
            runtime.set_mcp_app_context(child.instance_id.clone(), context);
            json!({})
        }
        "ui/notifications/initialized" => json!({}),
        "wisp/escape" => {
            if let Some(owner) = app.get_webview(&child.owner) {
                owner.set_focus().map_err(|e| e.to_string())?;
                owner.eval("window.dispatchEvent(new KeyboardEvent('keydown', {key:'Escape', bubbles:true, cancelable:true}));").map_err(|e| e.to_string())?;
            }
            json!({})
        }
        _ => return Ok(jsonrpc_error(id, "Capability is not granted by Wisp")),
    };
    ensure_current(&state, &child)?;
    Ok(jsonrpc_result(id, result))
}

#[tauri::command]
pub(crate) async fn request_mcp_app_child_action(
    app: AppHandle,
    window: WorkspaceSurface,
    state: State<'_, AppState>,
    instance_id: String,
    handle: McpAppChildHandle,
    method: String,
    params: Value,
) -> Result<Value, String> {
    verify_owner(&state, &window, &instance_id)?;
    let child = app
        .state::<McpAppChildren>()
        .registry
        .lock()
        .unwrap()
        .get_by_instance(window.label(), &instance_id)?;
    ensure_current(&state, &child)?;
    if handle != child.handle {
        return Err(STALE.into());
    }
    if child.payload.pointer("/tool/name").and_then(Value::as_str) != Some("motif_open_workbench")
        || !matches!(
            method.as_str(),
            "wisp/motif-get-selection" | "wisp/motif-add-records" | "ui/notifications/tool-result"
        )
        || serde_json::to_vec(&params)
            .map_err(|e| e.to_string())?
            .len()
            > crate::MAX_MCP_APP_RESULT_BYTES
    {
        return Err("MCP App host action is not permitted or is oversized".into());
    }
    let request_id = uuid::Uuid::new_v4().to_string();
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.state::<McpAppChildren>()
        .actions
        .lock()
        .unwrap()
        .insert(request_id.clone(), (child.handle.child_label.clone(), tx));
    let message = McpAppChildDelivery {
        kind: "request".into(),
        request_id: Some(request_id.clone()),
        method: Some(method),
        params,
    };
    if let Err(error) = mcp_app_children::deliver(&app, &child, &message) {
        app.state::<McpAppChildren>()
            .actions
            .lock()
            .unwrap()
            .remove(&request_id);
        return Err(error);
    }
    let result = match tokio::time::timeout(Duration::from_secs(5), rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err("MCP App action channel closed.".into()),
        Err(_) => {
            app.state::<McpAppChildren>()
                .actions
                .lock()
                .unwrap()
                .remove(&request_id);
            Err("MCP App did not respond in time.".into())
        }
    };
    ensure_current(&state, &child)?;
    result
}

#[tauri::command]
pub(crate) fn mcp_app_child_action_reply(
    webview: Webview,
    app: AppHandle,
    request_id: String,
    result: Option<Value>,
    error: Option<String>,
) -> Result<(), String> {
    let child = mcp_app_children::caller_child(&app, &webview)?;
    let children = app.state::<McpAppChildren>();
    let mut actions = children.actions.lock().unwrap();
    if actions
        .get(&request_id)
        .is_none_or(|(label, _)| label != &child.handle.child_label)
    {
        return Err(STALE.into());
    }
    if result.as_ref().is_some_and(|v| {
        serde_json::to_vec(v).map_or(true, |v| v.len() > crate::MAX_MCP_APP_RESULT_BYTES)
    }) {
        return Err("MCP App action result is oversized".into());
    }
    let entry = actions.remove(&request_id);
    let Some((label, tx)) = entry else {
        return Err(STALE.into());
    };
    if label != child.handle.child_label {
        return Err(STALE.into());
    }
    let _ = tx.send(match error {
        Some(error) => Err(error.chars().take(512).collect()),
        None => Ok(result.unwrap_or(Value::Null)),
    });
    Ok(())
}

#[tauri::command]
pub(crate) fn close_mcp_app_child(
    app: AppHandle,
    window: WorkspaceSurface,
    instance_id: String,
    owner_epoch: String,
    mount_serial: u64,
    reason: McpAppChildCloseReason,
) -> Result<bool, String> {
    mcp_app_frame_id(&instance_id)?;
    let retirement = app
        .state::<McpAppChildren>()
        .registry
        .lock()
        .unwrap()
        .close(
            window.label(),
            &owner_epoch,
            mount_serial,
            &instance_id,
            reason,
        );
    let had_child = !retirement.children.is_empty();
    finish_retirement(&app, retirement);
    Ok(had_child)
}
