// Tab operations with retry for transient Chrome errors (tab drag / moving).

function isTransientTabError(error) {
  var message = (error && error.message) || String(error || "");
  return /Tabs cannot be edited right now|user may be dragging|being dragged|No tab with id/i.test(message);
}

// Chrome can outlive its last window (background mode on Windows, the app on
// macOS). tabs.create without a windowId then has nowhere to go.
function isNoWindowError(error) {
  var message = (error && error.message) || String(error || "");
  return /No current window/i.test(message);
}

// A project's bound window was closed (or belongs to a browser run that
// ended). Wisp recognizes the window_gone code and binds a fresh window.
function isWindowGoneError(error) {
  var message = (error && error.message) || String(error || "");
  return /No window with id/i.test(message);
}

function windowGoneError(windowId, error) {
  var gone = new Error("window_gone: bound window " + windowId + " is no longer open (" + ((error && error.message) || String(error || "")) + ")");
  gone.code = "window_gone";
  gone.retryable = false;
  return gone;
}

async function withTabRetry(operation, attempts) {
  var max = attempts || 4;
  var lastError = null;
  for (var i = 0; i < max; i++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      if (!isTransientTabError(error) || i === max - 1) {
        var wrapped = new Error(error.message || String(error));
        wrapped.code = isTransientTabError(error) ? "TAB_BUSY" : "TAB_ERROR";
        wrapped.retryable = isTransientTabError(error);
        wrapped.operation = "tab";
        wrapped.attempts = i + 1;
        throw wrapped;
      }
      await new Promise(function (resolve) { setTimeout(resolve, 80 * Math.pow(2, i)); });
    }
  }
  throw lastError;
}

function createTabOps(chromeLike, managedIds) {
  var managed = managedIds || new Set();
  var pendingWindow = null;

  // Parallel opens that all find no window share the first new window
  // instead of each opening their own. Wisp serializes opens that bind a new
  // project window, so a dedicated window is never shared across projects.
  var openInNewWindow = async function (url, active) {
    if (pendingWindow) {
      var shared = await pendingWindow;
      return await withTabRetry(function () {
        return chromeLike.tabs.create({ windowId: shared.id, url: url, active: active ?? false });
      });
    }
    pendingWindow = withTabRetry(function () {
      return chromeLike.windows.create({ url: url, focused: !!active });
    });
    try {
      return (await pendingWindow).tabs[0];
    } finally {
      pendingWindow = null;
    }
  };

  var publicTab = function (tab) {
    if (!tab) return null;
    return {
      id: tab.id,
      url: tab.url || "",
      title: tab.title || "",
      status: tab.status || "",
      active: !!tab.active,
      windowId: tab.windowId,
      managed: managed.has(tab.id)
    };
  };

  return {
    markManaged: function (id) {
      if (Number.isInteger(id)) managed.add(id);
    },
    unmark: function (id) {
      managed.delete(id);
    },
    isManaged: function (id) {
      return managed.has(id);
    },
    releaseAll: function () {
      managed.clear();
      return true;
    },
    // placement.windowId opens in a project's bound window; placement.newWindow
    // opens a dedicated window (unfocused unless active) for Wisp to bind.
    // Without placement the tab goes to the current window, as before.
    create: async function (url, active, placement) {
      var windowId = placement && Number.isInteger(placement.windowId) ? placement.windowId : null;
      var newWindow = !!(placement && placement.newWindow) && windowId === null;
      var tab;
      if (windowId !== null) {
        try {
          tab = await withTabRetry(function () {
            return chromeLike.tabs.create({ windowId: windowId, url: url, active: active ?? false });
          });
        } catch (error) {
          if (isWindowGoneError(error)) throw windowGoneError(windowId, error);
          throw error;
        }
      } else if (newWindow) {
        tab = await openInNewWindow(url, active);
      } else {
        try {
          tab = await withTabRetry(function () {
            return chromeLike.tabs.create({ url: url, active: active ?? false });
          });
        } catch (error) {
          if (!isNoWindowError(error)) throw error;
          tab = await openInNewWindow(url, active);
        }
      }
      managed.add(tab.id);
      return publicTab(tab);
    },
    close: async function (ids) {
      var closed = [];
      for (var i = 0; i < ids.length; i++) {
        var id = ids[i];
        try {
          await withTabRetry(function () { return chromeLike.tabs.remove(id); });
          closed.push(id);
          managed.delete(id);
        } catch (_) {}
      }
      return closed;
    },
    switchTo: async function (tabId) {
      var tab = await withTabRetry(function () {
        return chromeLike.tabs.update(tabId, { active: true });
      });
      await withTabRetry(function () {
        return chromeLike.windows.update(tab.windowId, { focused: true });
      });
      return { ok: true, tab: publicTab(tab) };
    },
    get: async function (tabId) {
      try {
        return publicTab(await chromeLike.tabs.get(tabId));
      } catch (_) {
        return null;
      }
    },
    publicTab: publicTab
  };
}

if (typeof self !== "undefined") {
  self.createTabOps = createTabOps;
  self.isTransientTabError = isTransientTabError;
  self.isNoWindowError = isNoWindowError;
  self.isWindowGoneError = isWindowGoneError;
  self.withTabRetry = withTabRetry;
}
