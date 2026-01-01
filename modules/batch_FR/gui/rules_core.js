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

// -------------------------------------------------------------------------
// * Defaults helpers
// -------------------------------------------------------------------------
function _getDefaultsObj() {
  const defaults = (gPayload && gPayload.defaults) || {};
  return defaults && typeof defaults === "object" ? defaults : {};
}

function _defaultsHasKey(key) {
  const defaults = _getDefaultsObj();
  if (!defaults || typeof defaults !== "object") {
    return false;
  }
  // Only treat an explicit key as "defaults provided".
  return Object.prototype.hasOwnProperty.call(defaults, key);
}

function _getDefaultGroupNameSet() {
  const defaults = _getDefaultsObj();
  const arr = defaults.default_group_names;
  if (Array.isArray(arr)) {
    return new Set(arr.map(function (x) { return String(x); }));
  }
  return new Set();
}

function _getDefaultRulePathSet() {
  const defaults = _getDefaultsObj();
  const arr = defaults.default_rule_paths;
  if (Array.isArray(arr)) {
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

// -------------------------------------------------------------------------
// * Group header checkbox helpers
// -------------------------------------------------------------------------

function updateGroupHeaderCheckbox(groupDiv) {
  if (!groupDiv) return;

  const headerCb = groupDiv.querySelector(".file-group-header .file-group-checkbox");
  if (!headerCb) return;

  // Only consider visible file checkboxes (respects collapsed folders)
  const fileCbs = Array.from(
    groupDiv.querySelectorAll(".file-group-body .file-checkbox")
  ).filter(function (cb) {
    // offsetParent is null when the element (or its ancestor) is display:none
    return cb.offsetParent !== null;
  });
  const total = fileCbs.length;
  let checked = 0;

  fileCbs.forEach(function (cb) {
    if (cb.checked) checked++;
  });

  // If there are no visible files, show unchecked + not indeterminate
  if (!total) {
    headerCb.checked = false;
    headerCb.indeterminate = false;
    return;
  }

  headerCb.checked = checked === total;
  headerCb.indeterminate = checked > 0 && checked < total;
}

function updateAllGroupHeaderCheckboxes() {
  if (!filesContainerEl) return;
  const groupDivs = filesContainerEl.querySelectorAll(".file-group");
  groupDivs.forEach(function (groupDiv) {
    updateGroupHeaderCheckbox(groupDiv);
  });
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
  // Keep group header checkboxes in sync
  updateAllGroupHeaderCheckboxes();
}
function onSelectNone() {
  const cbs = filesContainerEl.querySelectorAll(".file-checkbox");
  cbs.forEach(function (cb) {
    cb.checked = false;
  });
  // Keep group header checkboxes in sync
  updateAllGroupHeaderCheckboxes();
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

    // If user saved defaults (even empty), use them; otherwise keep legacy behavior.
    if (_defaultsHasKey("default_group_names")) {
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

    // Group-level checkbox (far right) to toggle all files in this group
    const groupCb = document.createElement("input");
    groupCb.type = "checkbox";
    groupCb.className = "file-group-checkbox";
    groupCb.dataset.groupId = groupId;

    // Prevent collapsing/expanding when clicking the checkbox
    groupCb.addEventListener("click", function (ev) {
      ev.stopPropagation();
    });

    groupCb.addEventListener("change", function (ev) {
      ev.stopPropagation();

      // Only toggle visible checkboxes (respects collapsed folders + filter)
      const fileCbs = Array.from(
        groupDiv.querySelectorAll(".file-group-body .file-checkbox")
      ).filter(function (cb) {
        return cb.offsetParent !== null;
      });

      fileCbs.forEach(function (cb) {
        cb.checked = !!groupCb.checked;
      });

      // Ensure header state is correct (checked/indeterminate)
      updateGroupHeaderCheckbox(groupDiv);
    });

    header.appendChild(caret);
    header.appendChild(labelSpan);
    header.appendChild(groupCb);
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
      if (_defaultsHasKey("default_rule_paths")) {
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

      // Keep the group checkbox in sync when individual files are toggled
      cb.addEventListener("change", function () {
        updateGroupHeaderCheckbox(groupDiv);
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

    // Initialize group checkbox state after rendering all file rows
    updateGroupHeaderCheckbox(groupDiv);

    filesContainerEl.appendChild(groupDiv);
  });
}

