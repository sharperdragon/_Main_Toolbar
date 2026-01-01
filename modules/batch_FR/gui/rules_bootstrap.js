

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
