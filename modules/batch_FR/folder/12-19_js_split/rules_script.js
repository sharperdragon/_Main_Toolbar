// --- Bridge helper --------------------------------------------------------
function sendToPython(message) {
  var payload = "batchFr:" + JSON.stringify(message);
  if (window.pycmd) {
    pycmd(payload);
  } else if (window.external && window.external.pycmd) {
    window.external.pycmd(payload);
  }
}

// --- State ------------------------------------------------------------
let gPayload = null;

let groupsListEl,
  filesContainerEl,
  filterEl,
  statusLineEl,
  extensiveDebugEl,
  favoritesModalEl,
  favoritesAvailableListEl,
  favoritesSelectedListEl,
  favoritesFilterEl,
  favoritesAddBtn,
  favoritesRemoveBtn,
  // Settings modal elements (tabbed)
  settingsModalEl,
  settingsSaveBtn,
  settingsCancelBtn,
  settingsCloseBtn,
  settingsGroupsChecklistEl,
  settingsRulesFilterEl,
  settingsRulesSelectAllBtn,
  settingsRulesSelectNoneBtn,
  settingsFilesContainerEl,
  settingsTabButtons;

document.addEventListener("DOMContentLoaded", function () {
  groupsListEl = document.getElementById("groups-list");
  filesContainerEl = document.getElementById("files-container");
  filterEl = document.getElementById("filter");
  statusLineEl = document.getElementById("status-line");
  extensiveDebugEl = document.getElementById("extensive-debug");

  document.getElementById("select-all").addEventListener("click", onSelectAll);
  document.getElementById("select-none").addEventListener("click", onSelectNone);
  document.getElementById("ok-btn").addEventListener("click", onSubmit);
  document.getElementById("cancel-btn").addEventListener("click", onCancel);
  filterEl.addEventListener("input", onFilterChanged);

  // Favorites modal elements
  favoritesModalEl = document.getElementById("favorites-modal");
  favoritesAvailableListEl = document.getElementById("favorites-available-list");
  favoritesSelectedListEl = document.getElementById("favorites-selected-list");
  favoritesFilterEl = document.getElementById("favorites-filter");
  favoritesAddBtn = document.getElementById("favorites-btn-add");
  favoritesRemoveBtn = document.getElementById("favorites-btn-remove");

  // Favorites button: open inline favorites manager modal
  const favBtn = document.getElementById("favorites-btn");
  if (favBtn) {
    favBtn.addEventListener("click", openFavoritesModal);
  }

  const favClose = document.getElementById("favorites-close-btn");
  const favCancel = document.getElementById("favorites-cancel");
  const favSave = document.getElementById("favorites-save");

  if (favClose) {
    favClose.addEventListener("click", closeFavoritesModal);
  }
  if (favCancel) {
    favCancel.addEventListener("click", closeFavoritesModal);
  }
  if (favSave) {
    favSave.addEventListener("click", onFavoritesSave);
  }

  if (favoritesFilterEl) {
    favoritesFilterEl.addEventListener("input", onFavoritesFilterChanged);
  }
  if (favoritesAddBtn) {
    favoritesAddBtn.addEventListener("click", onFavoritesAdd);
  }
  if (favoritesRemoveBtn) {
    favoritesRemoveBtn.addEventListener("click", onFavoritesRemove);
  }

  // ------------------------------------------------------------------
  // * Settings modal: default selections (groups / rule files)
  // ------------------------------------------------------------------
  settingsModalEl = document.getElementById("settings-modal");
  settingsSaveBtn = document.getElementById("settings-save");
  settingsCancelBtn = document.getElementById("settings-cancel");
  settingsCloseBtn = document.getElementById("settings-close-btn");

  // New Settings UI elements (tabbed)
  settingsGroupsChecklistEl = document.getElementById("settings-groups-checklist");
  settingsRulesFilterEl = document.getElementById("settings-rules-filter");
  settingsRulesSelectAllBtn = document.getElementById("settings-rules-select-all");
  settingsRulesSelectNoneBtn = document.getElementById("settings-rules-select-none");
  settingsFilesContainerEl = document.getElementById("settings-files-container");
  settingsTabButtons = Array.from(document.querySelectorAll(".settings-tab"));

  const settingsBtn = document.getElementById("settings-btn");
  if (settingsBtn) {
    settingsBtn.addEventListener("click", openSettingsModal);
  }

  if (settingsCloseBtn) {
    settingsCloseBtn.addEventListener("click", closeSettingsModal);
  }
  if (settingsCancelBtn) {
    settingsCancelBtn.addEventListener("click", closeSettingsModal);
  }
  if (settingsSaveBtn) {
    settingsSaveBtn.addEventListener("click", onSettingsSave);
  }

  if (settingsRulesFilterEl) {
    settingsRulesFilterEl.addEventListener("input", function () {
      renderSettingsRuleFiles();
    });
  }
  if (settingsRulesSelectAllBtn) {
    settingsRulesSelectAllBtn.addEventListener("click", function () {
      settingsSelectAllVisibleRules(true);
    });
  }
  if (settingsRulesSelectNoneBtn) {
    settingsRulesSelectNoneBtn.addEventListener("click", function () {
      settingsSelectAllVisibleRules(false);
    });
  }

  if (settingsTabButtons && settingsTabButtons.length) {
    settingsTabButtons.forEach(function (btn) {
      btn.addEventListener("click", function () {
        const tab = btn.getAttribute("data-tab") || "groups";
        settingsActivateTab(tab);
      });
    });
  }

  // Tell Python we are ready for initial data
  sendToPython({ command: "ready" });
});

// Called from Python with initial context
window.batchFrInit = function (payload) {
  gPayload = payload || { groups: [], defaults: { dry_run: true } };

  const defaults = (gPayload && gPayload.defaults) || {};

  // Initialize the extensive-debug checkbox from defaults when present
  if (extensiveDebugEl) {
    extensiveDebugEl.checked = !!defaults.extensive_debug;
  }

  renderGroups();
  renderFiles();
  updateStatus("");
};
// -------------------------------------------------------------------------
// * Defaults helpers
// -------------------------------------------------------------------------
function _getDefaultsObj() {
  const defaults = (gPayload && gPayload.defaults) || {};
  return defaults && typeof defaults === "object" ? defaults : {};
}

function _getDefaultGroupNameSet() {
  const defaults = _getDefaultsObj();
  const arr = defaults.default_group_names;
  if (Array.isArray(arr) && arr.length) {
    return new Set(arr.map(function (x) { return String(x); }));
  }
  return new Set();
}

function _getDefaultRulePathSet() {
  const defaults = _getDefaultsObj();
  const arr = defaults.default_rule_paths;
  if (Array.isArray(arr) && arr.length) {
    return new Set(arr.map(function (x) { return String(x); }));
  }
  return new Set();
}

// -------------------------------------------------------------------------
// * Shared path + folder tree helpers (Main + Settings)
// -------------------------------------------------------------------------

function splitPathParts(rawPath) {
  return String(rawPath || "").split(/[\\/]/).filter(Boolean);
}

function stripRulesAnchor(parts) {
  // Try to anchor nesting under the "rules" directory if present.
  // This makes nesting stable even when group names are not path segments.
  if (!Array.isArray(parts) || !parts.length) {
    return parts || [];
  }
  for (let i = 0; i < parts.length; i++) {
    if (String(parts[i]).toLowerCase() === "rules") {
      return parts.slice(i + 1);
    }
  }
  return parts;
}

function getFolderPartsAndLeaf(groupName, f) {
  const rawPath = (f && f.path) ? String(f.path) : "";
  let parts = splitPathParts(rawPath);
  parts = stripRulesAnchor(parts);

  let subParts = [];
  if (parts.length) {
    const gName = String(groupName || "");
    const idx = gName ? parts.lastIndexOf(gName) : -1;

    if (idx !== -1 && idx + 1 < parts.length) {
      // Prefer everything after the group folder when present
      subParts = parts.slice(idx + 1);
    } else {
      // Otherwise nest using the anchored relative path itself
      subParts = parts.slice(0);
    }
  }

  // Ensure we have a leaf
  const fallbackLeaf = (f && f.name) ? String(f.name) : (parts.length ? String(parts[parts.length - 1]) : rawPath);
  if (!subParts.length) {
    subParts = [fallbackLeaf];
  }

  const folderParts = subParts.slice(0, -1);
  const leafName = String(subParts[subParts.length - 1] || fallbackLeaf || "");
  return { folderParts: folderParts, leafName: leafName };
}

function ensureNestedFolders(parentEl, folderCache, basePrefix, folderParts, css, forceOpen) {
  if (!parentEl || !Array.isArray(folderParts) || !folderParts.length) {
    return parentEl;
  }

  let parent = parentEl;
  let prefix = String(basePrefix || "");
  const cache = folderCache || {};

  folderParts.forEach(function (folder) {
    const fname = String(folder || "");
    prefix = prefix + "/" + fname;

    let container = cache[prefix];
    if (!container) {
      const folderDiv = document.createElement("div");
      folderDiv.className = css.folderDivClass;
      folderDiv.setAttribute("data-open", "1");

      const folderHeader = document.createElement("div");
      folderHeader.className = css.headerClass;

      const subCaret = document.createElement("span");
      subCaret.className = "hy-caret";
      subCaret.textContent = "▼";

      const nameSpan = document.createElement("span");
      nameSpan.className = css.titleClass;
      nameSpan.textContent = fname;

      folderHeader.appendChild(subCaret);
      folderHeader.appendChild(nameSpan);
      folderDiv.appendChild(folderHeader);

      const folderBody = document.createElement("div");
      folderBody.className = css.bodyClass;
      folderDiv.appendChild(folderBody);

      // Toggle handler (unless we are forcing open due to filter)
      if (!forceOpen) {
        folderHeader.addEventListener("click", function () {
          const open = folderDiv.getAttribute("data-open") === "1";
          folderDiv.setAttribute("data-open", open ? "0" : "1");
          folderBody.style.display = open ? "none" : "block";
          subCaret.textContent = open ? "▶" : "▼";
        });
      } else {
        folderDiv.setAttribute("data-open", "1");
        folderBody.style.display = "block";
        subCaret.textContent = "▼";
      }

      parent.appendChild(folderDiv);
      container = folderBody;
      cache[prefix] = container;
    }

    parent = container;
  });

  return parent;
}

// Python may call this after saving settings to refresh defaults immediately
window.batchFrSetDefaults = function (defaults) {
  if (!gPayload) {
    gPayload = { groups: [], defaults: { dry_run: true } };
  }
  const existing = _getDefaultsObj();
  const incoming = (defaults && typeof defaults === "object") ? defaults : {};
  gPayload.defaults = Object.assign({}, existing, incoming);

  // Re-render to apply the new default selection logic
  renderGroups();
  renderFiles();
};

function getExtensiveDebug() {
  // Prefer the actual checkbox if it exists
  if (extensiveDebugEl) {
    return !!extensiveDebugEl.checked;
  }
  // Fallback: use defaults from the payload so backend can still see a value
  const defaults = (gPayload && gPayload.defaults) || {};
  return !!defaults.extensive_debug;
}

// --- Rendering: groups ----------------------------------------------------

function renderGroups() {
  groupsListEl.innerHTML = "";
  const groups = (gPayload && gPayload.groups) || [];
  groups.forEach(function (group) {
    const wrap = document.createElement("div");
    wrap.className = "group-item";

    const cb = document.createElement("input");
    cb.type = "checkbox";

    const name = (group.name || "").trim();
    const lower = name.toLowerCase();

    const defaultGroups = _getDefaultGroupNameSet();

    // If user saved defaults, use them; otherwise keep legacy behavior.
    if (defaultGroups.size > 0) {
      cb.checked = defaultGroups.has(name);
    } else {
      cb.checked = !lower.startsWith("z");
    }

    cb.dataset.groupName = group.name;

    const label = document.createElement("span");
    label.textContent = group.name;

    cb.addEventListener("change", function () {
      renderFiles();
    });

    wrap.appendChild(cb);
    wrap.appendChild(label);
    groupsListEl.appendChild(wrap);
  });
}

function getSelectedGroupNames() {
  const cbs = groupsListEl.querySelectorAll('input[type="checkbox"]');
  const names = [];
  cbs.forEach(function (cb) {
    if (cb.checked) {
      names.push(cb.dataset.groupName);
    }
  });
  return names;
}

// --- Rendering: files (with collapsible groups) ---------------------------

function renderFiles() {
  filesContainerEl.innerHTML = "";

  if (!gPayload) {
    return;
  }

  const groups = gPayload.groups || [];
  const selectedGroups = new Set(getSelectedGroupNames());
  const filterText = (filterEl.value || "").trim().toLowerCase();

  groups.forEach(function (group) {
    if (!selectedGroups.has(group.name)) {
      return;
    }

    const files = group.files || [];
    const filteredFiles = files.filter(function (f) {
      if (!filterText) {
        return true;
      }
      const haystack = String(
        (f.label || "") + " " + (f.alias || "") + " " + (f.name || "")
      ).toLowerCase();
      return haystack.indexOf(filterText) !== -1;
    });

    if (!filteredFiles.length) {
      return;
    }

    const groupId = "g_" + group.name.replace(/\W+/g, "_");

    const groupDiv = document.createElement("div");
    groupDiv.className = "file-group";
    groupDiv.dataset.groupId = groupId;
    groupDiv.dataset.open = "1"; // open by default

    const header = document.createElement("div");
    header.className = "file-group-header";

    const caret = document.createElement("span");
    caret.className = "hy-caret";
    caret.textContent = "▼";

    const labelSpan = document.createElement("span");
    labelSpan.className = "file-group-label";
    labelSpan.textContent = group.name + " (" + filteredFiles.length + " files)";

    header.appendChild(caret);
    header.appendChild(labelSpan);
    groupDiv.appendChild(header);

    const body = document.createElement("div");
    body.className = "file-group-body";
    body.dataset.parentId = groupId;
    groupDiv.appendChild(body);

    // Toggle expand/collapse when header clicked
    header.addEventListener("click", function () {
      toggleGroupPanel(groupDiv);
    });

    // Nested folders inside group body, based on file paths
    const folderCache = {};

    filteredFiles.forEach(function (f) {
      // Compute folder nesting parts using the shared helper
      const partsInfo = getFolderPartsAndLeaf(group.name, f);
      const folderParts = partsInfo.folderParts;
      const fileLeafName = partsInfo.leafName;

      // Build / reuse nested folder containers (shared)
      const parent = ensureNestedFolders(
        body,
        folderCache,
        group.name,
        folderParts,
        {
          folderDivClass: "file-subfolder",
          headerClass: "file-subfolder-header",
          titleClass: "file-subfolder-label",
          bodyClass: "file-subfolder-body",
        },
        false
      );

      // Leaf: actual file row (same behavior as before)
      const item = document.createElement("div");
      item.className = "file-item";
      item.dataset.groupId = groupId;
      item.dataset.path = f.path;

      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.className = "file-checkbox";

      const defaultRulePaths = _getDefaultRulePathSet();
      if (defaultRulePaths.size > 0) {
        cb.checked = !!(f.path && defaultRulePaths.has(String(f.path)));
      } else {
        cb.checked = true;
      }

      cb.dataset.path = f.path;

      const main = document.createElement("span");
      main.className = "file-label-main";
      main.textContent = f.label || f.name || fileLeafName;

      const aliasSpan = document.createElement("span");
      aliasSpan.className = "file-label-alias";
      if (f.alias) {
        aliasSpan.textContent = "(" + f.alias + ")";
      }

      cb.addEventListener("click", function (ev) {
        ev.stopPropagation(); // don’t trigger row click
      });

      item.addEventListener("click", function () {
        document.querySelectorAll(".file-item.selected").forEach(function (el) {
          el.classList.remove("selected");
        });
        item.classList.add("selected");
        updateStatusForFile(group.name, f);

        if (f.path) {
          sendToPython({
            command: "preview",
            path: f.path,
          });
        }
      });

      item.appendChild(cb);
      item.appendChild(main);
      if (f.alias) {
        item.appendChild(aliasSpan);
      }
      parent.appendChild(item);
    });

    filesContainerEl.appendChild(groupDiv);
  });
}

// --- Favorites modal helpers ------------------------------------------------

let favoritesSelectedItem = null;
let favoritesActiveList = null; // "available" or "selected"

function favoritesClearSelection() {
  if (favoritesSelectedItem) {
    favoritesSelectedItem.classList.remove("is-selected");
  }
  favoritesSelectedItem = null;
  favoritesUpdateButtons();
}

function favoritesSelectItem(item) {
  if (favoritesSelectedItem === item) {
    favoritesClearSelection();
    return;
  }
  if (favoritesSelectedItem) {
    favoritesSelectedItem.classList.remove("is-selected");
  }
  favoritesSelectedItem = item;
  favoritesSelectedItem.classList.add("is-selected");
  favoritesUpdateButtons();
}

function favoritesUpdateButtons() {
  if (!favoritesAddBtn || !favoritesRemoveBtn) {
    return;
  }
  favoritesAddBtn.disabled = !(
    favoritesSelectedItem &&
    favoritesSelectedItem.parentElement === favoritesAvailableListEl
  );
  favoritesRemoveBtn.disabled = !(
    favoritesSelectedItem &&
    favoritesSelectedItem.parentElement === favoritesSelectedListEl
  );
}

function favoritesAttachItemClick(li) {
  li.addEventListener("click", function () {
    favoritesSelectItem(li);

    if (li.parentElement === favoritesAvailableListEl) {
      favoritesActiveList = "available";
    } else if (li.parentElement === favoritesSelectedListEl) {
      favoritesActiveList = "selected";
    }
  });
}

function favoritesVisibleItems(listEl) {
  const items = Array.from(listEl.querySelectorAll(".favorites-item"));
  return items.filter(function (li) {
    return li.style.display !== "none";
  });
}

function openFavoritesModal() {
  if (
    !favoritesModalEl ||
    !favoritesAvailableListEl ||
    !favoritesSelectedListEl ||
    !gPayload ||
    !Array.isArray(gPayload.groups)
  ) {
    return;
  }

  favoritesAvailableListEl.innerHTML = "";
  favoritesSelectedListEl.innerHTML = "";
  favoritesSelectedItem = null;
  favoritesUpdateButtons();

  if (favoritesFilterEl) {
    favoritesFilterEl.value = "";
  }

  const seen = new Set();

  gPayload.groups.forEach(function (group) {
    if (!group.files) {
      return;
    }
    (group.files || []).forEach(function (f) {
      if (!f.path || seen.has(f.path)) {
        return;
      }
      seen.add(f.path);

      const li = document.createElement("li");
      li.className = "favorites-item";
      li.dataset.path = f.path;
      li.dataset.name = f.name || "";
      li.dataset.group = group.name || "";

      const labelText =
        "[" + (group.name || "unknown") + "] " +
        (f.label || f.name || f.path);
      li.textContent = labelText;

      favoritesAttachItemClick(li);

      if (f.favorite) {
        favoritesSelectedListEl.appendChild(li);
      } else {
        favoritesAvailableListEl.appendChild(li);
      }
    });
  });

  favoritesModalEl.classList.remove("hidden");
  favoritesUpdateButtons();

  // Focus filter for immediate typing
  if (favoritesFilterEl) {
    favoritesFilterEl.focus();
  }

  // Install keyboard navigation handler
  favoritesModalEl.addEventListener("keydown", favoritesKeyHandler);
}

function closeFavoritesModal() {
  if (favoritesModalEl) {
    favoritesModalEl.classList.add("hidden");
    favoritesModalEl.removeEventListener("keydown", favoritesKeyHandler);
  }
  favoritesSelectedItem = null;
  favoritesActiveList = null;
  favoritesUpdateButtons();
}

function favoritesKeyHandler(ev) {
  const key = ev.key;
  const target = ev.target;

  // Always allow ESC to close
  if (key === "Escape") {
    ev.preventDefault();
    closeFavoritesModal();
    return;
  }

  // If typing in an input (like the filter), ignore navigation keys
  if (target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA")) {
    return;
  }

  // Up / Down change selection in the active list
  if (key === "ArrowUp" || key === "ArrowDown") {
    ev.preventDefault();
    favoritesMoveSelection(key === "ArrowDown" ? 1 : -1);
    return;
  }

  // Right / Left / Enter / Space move items between lists
  if (
    key === "ArrowRight" ||
    key === "ArrowLeft" ||
    key === "Enter" ||
    key === " "
  ) {
    ev.preventDefault();
    const towardsFavorites =
      key === "ArrowRight" || key === "Enter" || key === " ";
    favoritesMoveBetweenLists(towardsFavorites);
  }
}

function favoritesMoveSelection(delta) {
  let listEl = null;

  // Decide which list is active
  if (!favoritesActiveList) {
    if (favoritesSelectedItem) {
      listEl =
        favoritesSelectedItem.parentElement === favoritesSelectedListEl
          ? favoritesSelectedListEl
          : favoritesAvailableListEl;
    } else {
      listEl = favoritesAvailableListEl;
    }
  } else {
    listEl =
      favoritesActiveList === "selected"
        ? favoritesSelectedListEl
        : favoritesAvailableListEl;
  }

  if (!listEl) {
    return;
  }

  const items = favoritesVisibleItems(listEl);
  if (!items.length) {
    return;
  }

  let idx = items.indexOf(favoritesSelectedItem);
  if (idx === -1) {
    idx = delta > 0 ? 0 : items.length - 1;
  } else {
    idx = (idx + delta + items.length) % items.length;
  }

  const nextItem = items[idx];
  favoritesSelectItem(nextItem);
  nextItem.scrollIntoView({ block: "nearest" });

  favoritesActiveList =
    listEl === favoritesSelectedListEl ? "selected" : "available";
}

function favoritesMoveBetweenLists(towardsFavorites) {
  if (!favoritesSelectedItem) {
    return;
  }
  const parent = favoritesSelectedItem.parentElement;

  if (towardsFavorites) {
    // available -> selected
    if (parent === favoritesAvailableListEl && !favoritesAddBtn.disabled) {
      onFavoritesAdd();
      favoritesActiveList = "selected";
    }
  } else {
    // selected -> available
    if (parent === favoritesSelectedListEl && !favoritesRemoveBtn.disabled) {
      onFavoritesRemove();
      favoritesActiveList = "available";
    }
  }
}

function onFavoritesAdd() {
  if (
    !favoritesSelectedItem ||
    favoritesSelectedItem.parentElement !== favoritesAvailableListEl
  ) {
    return;
  }
  favoritesSelectedListEl.appendChild(favoritesSelectedItem);
  favoritesSelectedItem.scrollIntoView({ block: "nearest" });
  favoritesUpdateButtons();
}

function onFavoritesRemove() {
  if (
    !favoritesSelectedItem ||
    favoritesSelectedItem.parentElement !== favoritesSelectedListEl
  ) {
    return;
  }
  favoritesAvailableListEl.appendChild(favoritesSelectedItem);
  favoritesSelectedItem.scrollIntoView({ block: "nearest" });
  favoritesUpdateButtons();
}

function onFavoritesFilterChanged() {
  if (!favoritesFilterEl || !favoritesModalEl) {
    return;
  }
  const text = favoritesFilterEl.value.trim().toLowerCase();
  const allItems = favoritesModalEl.querySelectorAll(".favorites-item");
  allItems.forEach(function (li) {
    const label = li.textContent || "";
    li.style.display =
      !text || label.toLowerCase().indexOf(text) !== -1 ? "" : "none";
  });
}

function onFavoritesSave() {
  if (!gPayload || !Array.isArray(gPayload.groups)) {
    closeFavoritesModal();
    return;
  }

  const desiredFavPaths = new Set();
  if (favoritesSelectedListEl) {
    favoritesSelectedListEl
      .querySelectorAll(".favorites-item")
      .forEach(function (li) {
        if (li.dataset.path) {
          desiredFavPaths.add(li.dataset.path);
        }
      });
  }

  const changed = [];

  gPayload.groups.forEach(function (group) {
    if (!group.files) {
      return;
    }
    (group.files || []).forEach(function (f) {
      if (!f.path) {
        return;
      }
      const wantFav = desiredFavPaths.has(f.path);
      const before = !!f.favorite;
      if (before !== wantFav) {
        f.favorite = wantFav;
        changed.push({ path: f.path, favorite: wantFav });
      }
    });
  });

  // Notify Python of changes so favorites are persisted
  changed.forEach(function (ch) {
    sendToPython({
      command: "toggle_favorite",
      path: ch.path,
      favorite: ch.favorite,
    });
  });

  // Rebuild the synthetic "★ Favorites" group and refresh UI
  syncFavoritesGroupInPayload();
  closeFavoritesModal();
}

// Keep the synthetic "★ Favorites" group in sync with current favorite flags
function syncFavoritesGroupInPayload() {
  if (!gPayload || !Array.isArray(gPayload.groups)) {
    return;
  }

  const groups = gPayload.groups;
  let favoritesGroup = null;

  // Find existing Favorites group if present
  for (let i = 0; i < groups.length; i++) {
    if (groups[i].name === "★ Favorites") {
      favoritesGroup = groups[i];
      break;
    }
  }

  if (!favoritesGroup) {
    favoritesGroup = { name: "★ Favorites", files: [] };
    groups.unshift(favoritesGroup);
  }

  const seenPaths = new Set();
  favoritesGroup.files = [];

  groups.forEach(function (group) {
    if (group.name === "★ Favorites") {
      return;
    }
    (group.files || []).forEach(function (f) {
      if (f.favorite && f.path && !seenPaths.has(f.path)) {
        seenPaths.add(f.path);
        favoritesGroup.files.push(f);
      }
    });
  });

  // If no favorites remain, remove the Favorites group entirely
  if (favoritesGroup.files.length === 0) {
    const idx = groups.indexOf(favoritesGroup);
    if (idx !== -1) {
      groups.splice(idx, 1);
    }
  }

  // Re-render files so the UI reflects updated favorites state
  renderFiles();
}

function toggleGroupPanel(groupDiv) {
  if (!groupDiv) return;
  const open = groupDiv.getAttribute("data-open") === "1";
  const nextOpen = !open;
  groupDiv.setAttribute("data-open", nextOpen ? "1" : "0");

  const body = groupDiv.querySelector(".file-group-body");
  const caret = groupDiv.querySelector(".hy-caret");

  if (body) {
    body.style.display = nextOpen ? "block" : "none";
  }
  if (caret) {
    caret.textContent = nextOpen ? "▼" : "▶";
  }
}


function toggleFolderPanel(folderDiv) {
  if (!folderDiv) return;
  const open = folderDiv.getAttribute("data-open") === "1";
  const nextOpen = !open;
  folderDiv.setAttribute("data-open", nextOpen ? "1" : "0");

  const body = folderDiv.querySelector(".file-subfolder-body");
  const caret = folderDiv.querySelector(".hy-caret");

  if (body) {
    body.style.display = nextOpen ? "block" : "none";
  }
  if (caret) {
    caret.textContent = nextOpen ? "▼" : "▶";
  }
}

// --- Status line helpers --------------------------------------------------

function updateStatus(text) {
  // ! Safely handle missing status line so UI doesn't break if it's moved or omitted
  if (!statusLineEl) {
    statusLineEl = document.getElementById("status-line");
  }

  if (!statusLineEl) {
    // Nothing to update; avoid throwing errors that stop rendering
    return;
  }

  statusLineEl.textContent = text || "";
}

function updateStatusForFile(groupName, f) {
  const bits = [];
  if (f.label) {
    bits.push(f.label);
  } else {
    bits.push(f.name);
  }
  if (f.alias) {
    bits.push("alias: " + f.alias);
  }
  if (f.path) {
    bits.push(f.path);
  }
  updateStatus(bits.join(" — "));
}

// --- Actions --------------------------------------------------------------

function onFilterChanged() {
  renderFiles();
}

function onSelectAll() {
  const cbs = filesContainerEl.querySelectorAll(".file-checkbox");
  cbs.forEach(function (cb) {
    cb.checked = true;
  });
}

function onSelectNone() {
  const cbs = filesContainerEl.querySelectorAll(".file-checkbox");
  cbs.forEach(function (cb) {
    cb.checked = false;
  });
}

function gatherSelectedFiles() {
  const cbs = filesContainerEl.querySelectorAll(".file-checkbox:checked");
  const paths = [];
  cbs.forEach(function (cb) {
    if (cb.dataset.path) {
      paths.push(cb.dataset.path);
    }
  });
  return paths;
}

function getDryRun() {
  const mode = document.querySelector('input[name="mode"]:checked');
  return !mode || mode.value === "dry";
}

function onSubmit() {
  const files = gatherSelectedFiles();
  if (!files.length) {
    // Do nothing if nothing selected; Python will ignore
    return;
  }
  const msg = {
    command: "submit",
    dry_run: getDryRun(),
    extensive_debug: getExtensiveDebug(),
    files: files,
  };
  sendToPython(msg);
}

function onCancel() {
  sendToPython({ command: "cancel" });
}

// --- Preview callback from Python ----------------------------------------
window.batchFrSetPreview = function (payload) {
  const pre = document.getElementById("rule-preview");
  if (!pre) {
    return;
  }

  let text = "";
  if (payload && typeof payload.text === "string") {
    text = payload.text;
  }

  if (!text.trim()) {
    pre.textContent = "No content to display for this file.";
  } else {
    pre.textContent = text;
  }
};

// --- Settings modal helpers -----------------------------------------------

// In-settings state (do not mutate main UI selection until Save)
let gSettingsDefaultGroupNames = new Set();
let gSettingsDefaultRulePathSet = new Set();

function settingsActivateTab(tabName) {
  const tabs = Array.from(document.querySelectorAll(".settings-tab"));
  const panels = Array.from(document.querySelectorAll(".settings-tab-panel"));

  tabs.forEach(function (t) {
    const name = t.getAttribute("data-tab");
    t.classList.toggle("is-active", name === tabName);
  });

  panels.forEach(function (p) {
    const name = p.getAttribute("data-panel");
    p.classList.toggle("is-active", name === tabName);
  });
}

function openSettingsModal() {
  if (!settingsModalEl || !gPayload || !Array.isArray(gPayload.groups)) {
    return;
  }

  const defaults = _getDefaultsObj();

  gSettingsDefaultGroupNames = new Set(
    Array.isArray(defaults.default_group_names)
      ? defaults.default_group_names.map(function (x) { return String(x); })
      : []
  );

  gSettingsDefaultRulePathSet = new Set(
    Array.isArray(defaults.default_rule_paths)
      ? defaults.default_rule_paths.map(function (x) { return String(x); })
      : []
  );

  if (settingsRulesFilterEl) {
    settingsRulesFilterEl.value = "";
  }

  renderSettingsGroups();
  renderSettingsRuleFiles();
  settingsActivateTab("groups");

  settingsModalEl.classList.remove("hidden");
}

function closeSettingsModal() {
  if (settingsModalEl) {
    settingsModalEl.classList.add("hidden");
  }
}

function renderSettingsGroups() {
  if (!settingsGroupsChecklistEl || !gPayload || !Array.isArray(gPayload.groups)) {
    return;
  }

  settingsGroupsChecklistEl.innerHTML = "";

  const seen = new Set();
  (gPayload.groups || []).forEach(function (group) {
    const name = String(group.name || "").trim();
    if (!name || seen.has(name)) return;
    seen.add(name);

    if (name === "★ Favorites") return;

    const li = document.createElement("li");
    li.className = "settings-check-item";

    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.className = "settings-check";
    cb.dataset.groupName = name;
    cb.checked = gSettingsDefaultGroupNames.has(name);

    cb.addEventListener("change", function () {
      if (cb.checked) gSettingsDefaultGroupNames.add(name);
      else gSettingsDefaultGroupNames.delete(name);
    });

    const label = document.createElement("span");
    label.className = "settings-check-label";
    label.textContent = name;

    li.appendChild(cb);
    li.appendChild(label);
    settingsGroupsChecklistEl.appendChild(li);
  });
}

function settingsRuleMatchesFilter(f, filterText) {
  if (!filterText) return true;
  const haystack = String((f.label || "") + " " + (f.alias || "") + " " + (f.name || "")).toLowerCase();
  return haystack.indexOf(filterText) !== -1;
}

function renderSettingsRuleFiles() {
  if (!settingsFilesContainerEl || !gPayload || !Array.isArray(gPayload.groups)) {
    return;
  }

  settingsFilesContainerEl.innerHTML = "";

  const filterText = (settingsRulesFilterEl && settingsRulesFilterEl.value)
    ? settingsRulesFilterEl.value.trim().toLowerCase()
    : "";

  (gPayload.groups || []).forEach(function (group) {
    const groupName = String(group.name || "").trim();
    if (!groupName || groupName === "★ Favorites") return;

    const files = Array.isArray(group.files) ? group.files : [];
    const filteredFiles = files.filter(function (f) {
      return settingsRuleMatchesFilter(f, filterText);
    });

    if (!filteredFiles.length) return;

    const groupDiv = document.createElement("div");
    groupDiv.className = "settings-file-group";
    groupDiv.setAttribute("data-open", "1");

    const header = document.createElement("div");
    header.className = "settings-file-group-header";

    const caret = document.createElement("span");
    caret.className = "hy-caret";
    caret.textContent = "▼";

    const title = document.createElement("span");
    title.className = "settings-file-group-title";
    title.textContent = groupName + " (" + filteredFiles.length + ")";

    header.appendChild(caret);
    header.appendChild(title);
    groupDiv.appendChild(header);

    const body = document.createElement("div");
    body.className = "settings-file-group-body";
    groupDiv.appendChild(body);

    if (!filterText) {
      header.addEventListener("click", function () {
        const open = groupDiv.getAttribute("data-open") === "1";
        groupDiv.setAttribute("data-open", open ? "0" : "1");
        body.style.display = open ? "none" : "block";
        caret.textContent = open ? "▶" : "▼";
      });
    } else {
      // When filtering, keep groups open so matches are visible
      groupDiv.setAttribute("data-open", "1");
      body.style.display = "block";
      caret.textContent = "▼";
    }

    const folderCache = {};

    filteredFiles.forEach(function (f) {
      // Compute folder nesting parts using the shared helper
      const partsInfo = getFolderPartsAndLeaf(groupName, f);
      const folderParts = partsInfo.folderParts;
      const fileLeafName = partsInfo.leafName;

      // If filtering, keep everything expanded so matches aren't hidden
      const forceOpen = !!filterText;

      // Build / reuse nested folder containers (shared)
      const parent = ensureNestedFolders(
        body,
        folderCache,
        groupName,
        folderParts,
        {
          folderDivClass: "settings-file-subfolder",
          headerClass: "settings-file-subfolder-header",
          titleClass: "settings-file-subfolder-title",
          bodyClass: "settings-file-subfolder-body",
        },
        forceOpen
      );

      const row = document.createElement("div");
      row.className = "settings-file-item";

      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.className = "settings-file-checkbox";
      cb.dataset.path = f.path;
      cb.checked = !!(f.path && gSettingsDefaultRulePathSet.has(String(f.path)));

      cb.addEventListener("change", function () {
        const p = String(cb.dataset.path || "");
        if (!p) return;
        if (cb.checked) gSettingsDefaultRulePathSet.add(p);
        else gSettingsDefaultRulePathSet.delete(p);
      });

      const label = document.createElement("span");
      label.className = "settings-file-label";
      label.textContent = f.label || f.name || fileLeafName;

      row.appendChild(cb);
      row.appendChild(label);
      parent.appendChild(row);
    });

    settingsFilesContainerEl.appendChild(groupDiv);
  });
}

function settingsSelectAllVisibleRules(checked) {
  if (!settingsFilesContainerEl) return;
  const cbs = settingsFilesContainerEl.querySelectorAll(".settings-file-checkbox");
  cbs.forEach(function (cb) {
    cb.checked = !!checked;
    const p = String(cb.dataset.path || "");
    if (!p) return;
    if (checked) gSettingsDefaultRulePathSet.add(p);
    else gSettingsDefaultRulePathSet.delete(p);
  });
}

function onSettingsSave() {
  if (!gPayload) {
    closeSettingsModal();
    return;
  }

  const nextDefaults = {
    default_group_names: Array.from(gSettingsDefaultGroupNames),
    default_rule_paths: Array.from(gSettingsDefaultRulePathSet),
  };

  sendToPython(Object.assign({ command: "save_default_selection" }, nextDefaults));

  // Apply immediately in the current session, even if Python doesn't push back
  const existing = _getDefaultsObj();
  if (!gPayload.defaults || typeof gPayload.defaults !== "object") {
    gPayload.defaults = { dry_run: true };
  }
  gPayload.defaults = Object.assign({}, existing, nextDefaults);

  // Re-render so the main UI reflects new defaults right now
  renderGroups();
  renderFiles();

  closeSettingsModal();
}