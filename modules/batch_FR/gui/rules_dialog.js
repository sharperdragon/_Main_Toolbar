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

    // Group-level checkbox (far right)
    const groupCb = document.createElement("input");
    groupCb.type = "checkbox";
    groupCb.className = "settings-file-group-checkbox";
    groupCb.dataset.groupName = groupName;

    // Prevent collapse toggle when clicking checkbox
    groupCb.addEventListener("click", function (ev) {
      ev.stopPropagation();
    });

    header.appendChild(caret);
    header.appendChild(title);
    header.appendChild(groupCb);
    groupDiv.appendChild(header);

    const body = document.createElement("div");
    body.className = "settings-file-group-body";
    groupDiv.appendChild(body);

    function updateSettingsGroupCheckbox() {
      const fileCbs = Array.from(
        body.querySelectorAll(".settings-file-checkbox")
      ).filter(function (cb) {
        return cb.offsetParent !== null;
      });

      if (!fileCbs.length) {
        groupCb.checked = false;
        groupCb.indeterminate = false;
        return;
      }

      let checked = 0;
      fileCbs.forEach(function (cb) {
        if (cb.checked) checked++;
      });

      groupCb.checked = checked === fileCbs.length;
      groupCb.indeterminate = checked > 0 && checked < fileCbs.length;
    }

    groupCb.addEventListener("change", function (ev) {
      ev.stopPropagation();

      const fileCbs = Array.from(
        body.querySelectorAll(".settings-file-checkbox")
      ).filter(function (cb) {
        return cb.offsetParent !== null;
      });

      fileCbs.forEach(function (cb) {
        cb.checked = !!groupCb.checked;
        const p = String(cb.dataset.path || "");
        if (!p) return;
        if (groupCb.checked) gSettingsDefaultRulePathSet.add(p);
        else gSettingsDefaultRulePathSet.delete(p);
      });

      updateSettingsGroupCheckbox();
    });

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
        updateSettingsGroupCheckbox();
      });

      const label = document.createElement("span");
      label.className = "settings-file-label";
      label.textContent = f.label || f.name || fileLeafName;

      row.appendChild(cb);
      row.appendChild(label);
      parent.appendChild(row);
    });

    // Initialize group checkbox state after rendering all file rows
    updateSettingsGroupCheckbox();

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