let model = []; // hydrated from Python
let dragIndex = null;
let selectedIndex = null; // currently selected row
let _draggingEl = null; // currently dragged <tr> element
let _markerEl = null; // visual insertion marker row
let _isDragging = false;       // pointer-driven drag active
let _dragStartIndex = null;    // index of the row where drag began

function _ensureDndStyles() {
  if (document.getElementById('mt-dnd-style')) return;
  const style = document.createElement('style');
  style.id = 'mt-dnd-style';
  style.textContent = `
    .tool-row.dragging { opacity: 0.6; }
    tr.dnd-insert-marker td {
      padding: 0 !important;
      border: none !important;
    }
    tr.dnd-insert-marker td::before {
      content: "";
      display: block;
      height: 0;
      border-top: 2px solid;
      opacity: 0.7;
      margin: 2px 0;
    }
    td.drag-cell { width: 24px; }
    body.mt-grabbing { cursor: grabbing !important; user-select: none !important; }
  `;
  document.head.appendChild(style);
}

function getDragAfterElement(tbody, y) {
  const rows = [...tbody.querySelectorAll('tr.tool-row:not(.dragging)')];
  return rows.reduce((closest, child) => {
    const box = child.getBoundingClientRect();
    const offset = y - (box.top + box.height / 2);
    if (offset < 0 && offset > closest.offset) {
      return { offset, element: child };
    } else {
      return closest;
    }
  }, { offset: Number.NEGATIVE_INFINITY, element: null }).element;
}

function _getColCount() {
  const first = document.querySelector('#tbody tr');
  if (first) return first.children.length || 7;
  return 7;
}

function _getOrCreateMarker() {
  if (_markerEl && _markerEl.isConnected) return _markerEl;
  _markerEl = document.createElement('tr');
  _markerEl.className = 'dnd-insert-marker';
  const td = document.createElement('td');
  td.colSpan = _getColCount();
  _markerEl.appendChild(td);
  return _markerEl;
}

function _placeMarkerBefore(tbody, beforeEl) {
  const m = _getOrCreateMarker();
  if (beforeEl) {
    tbody.insertBefore(m, beforeEl);
  } else {
    tbody.appendChild(m);
  }
}

function _removeMarker() {
  if (_markerEl && _markerEl.parentNode) {
    _markerEl.parentNode.removeChild(_markerEl);
  }
}

function _toSvgCandidate(path) {
  const clean = (path ?? "").toString().trim().replace(/\\/g, "/");
  if (!clean || clean.endsWith("/")) return "";

  const slash = clean.lastIndexOf("/");
  const dot = clean.lastIndexOf(".");
  const hasExt = dot > slash;
  if (!hasExt) return clean + ".svg";

  const ext = clean.slice(dot).toLowerCase();
  if (ext === ".svg") return clean;
  if (ext === ".png") return clean.slice(0, dot) + ".svg";
  return "";
}

function normalizeIcon(value) {
  const raw = (value ?? "").toString().trim().replace(/\\/g, "/");
  if (!raw) return "";

  if (raw.startsWith(":assets/")) return _toSvgCandidate(raw);
  if (raw.startsWith(":")) return "";
  if (raw.startsWith("/")) return _toSvgCandidate(raw);

  const rel = raw.startsWith("assets/") || raw.startsWith("icons/")
    ? raw
    : "icons/" + raw;
  return _toSvgCandidate(rel);
}

function rowHtml(r, i) {
  const esc = s => (s ?? "").toString().replace(/&/g,"&amp;").replace(/</g,"&lt;");
  const isSep = (r.type === "separator") || (r.name === "———");
  return `
    <tr class="tool-row" data-index="${i}" data-type="${isSep ? "separator" : "item"}">
      <td class="drag-cell">
        <span class="drag-handle" title="Drag to reorder" style="cursor:grab; user-select:none;">⋮⋮</span>
      </td>
      <td class="name-cell">
        <input value="${esc(r.name)}" placeholder="Name" onchange="onEdit(${i}, 'name', this.value)">
      </td>
      <td><input value="${esc(r.module)}" placeholder="Module (e.g., _Main_Toolbar.modules...)" onchange="onEdit(${i}, 'module', this.value)"></td>
      <td><input value="${esc(r.function)}" placeholder="Function" onchange="onEdit(${i}, 'function', this.value)"></td>
      <td><input value="${esc(r.submenu)}" placeholder="Submenu" onchange="onEdit(${i}, 'submenu', this.value)"></td>
      <td class="icon-cell">
        <input value="${esc(r.icon)}" placeholder="icon.svg" onchange="(function(el){ const v = normalizeIcon(el.value); el.value = v; onEdit(${i}, 'icon', v); document.querySelector('tr[data-index=\\"${i}\\"] .icon-preview')?.setAttribute('src', v); })(this)">
      </td>
      <td><input type="checkbox" ${r.enabled ? "checked": ""} onchange="onEdit(${i}, 'enabled', this.checked)"></td>
    </tr>
  `;
}

function selectRow(i) {
  selectedIndex = (typeof i === 'number' ? i : null);
  const tbody = document.getElementById('tbody');
  if (!tbody) return;
  tbody.querySelectorAll('tr').forEach((tr, idx) => {
    if (idx === selectedIndex) tr.classList.add('selected');
    else tr.classList.remove('selected');
  });
}

function render() {
  const tbody = document.getElementById("tbody");
  _ensureDndStyles();
  const prev = selectedIndex; // remember selection across rerenders
  tbody.innerHTML = model.map(rowHtml).join("");

  // Row-level listeners: selection only
  tbody.querySelectorAll("tr").forEach(tr => {
    tr.addEventListener("click", () => selectRow(+tr.dataset.index));
  });

  // ! Pointer-driven drag (robust in Qt WebEngine)
  tbody.addEventListener('mousedown', (e) => {
    const handle = e.target.closest('.drag-handle');
    if (!handle) return; // only start from handle
    const tr = handle.closest('tr.tool-row');
    if (!tr) return;
    if (tr.dataset.type === 'separator') return; // no dragging separators

    _isDragging = true;
    _dragStartIndex = +tr.dataset.index;
    _draggingEl = tr;
    tr.classList.add('dragging');
    document.body.classList.add('mt-grabbing');

    // show marker just after the current row initially
    _placeMarkerBefore(tbody, tr.nextElementSibling);
    e.preventDefault();
  });

  // move marker with pointer
  const _onMouseMove = (e) => {
    if (!_isDragging || !_draggingEl) return;
    const afterEl = getDragAfterElement(tbody, e.clientY);
    _placeMarkerBefore(tbody, afterEl);
  };

  // commit on mouse up anywhere
  const _onMouseUp = (e) => {
    if (!_isDragging || !_draggingEl) return;

    _isDragging = false;

    const rows = [...tbody.querySelectorAll('tr.tool-row')];
    let insertIndex = rows.length; // default to end
    if (_markerEl && _markerEl.parentNode === tbody) {
      const next = _markerEl.nextElementSibling;
      if (next && next.classList.contains('tool-row')) {
        insertIndex = rows.indexOf(next);
      }
    }

    const from = _dragStartIndex;
    let to = insertIndex;
    if (from < to) to -= 1;

    const [moved] = model.splice(from, 1);
    model.splice(to, 0, moved);

    if (_draggingEl) _draggingEl.classList.remove('dragging');
    _draggingEl = null;
    _dragStartIndex = null;
    document.body.classList.remove('mt-grabbing');
    _removeMarker();

    // re-render and select moved row
    render();
    selectRow(to);
  };

  // attach document-level listeners once per render (idempotent)
  // remove pre-existing to avoid duplicates
  document.removeEventListener('mousemove', _onMouseMove);
  document.removeEventListener('mouseup', _onMouseUp);
  document.addEventListener('mousemove', _onMouseMove);
  document.addEventListener('mouseup', _onMouseUp);

  // focusing an input selects the row
  tbody.querySelectorAll('input').forEach(inp => {
    inp.addEventListener('focus', (e) => {
      const tr = e.target.closest('tr');
      if (tr) selectRow(+tr.dataset.index);
    });
  });

  // restore previous selection if still valid
  if (prev != null && prev >= 0 && prev < model.length) selectRow(prev);

  // Reindex all rows' data-index to their current visual order
  [...tbody.querySelectorAll('tr')].forEach((tr, idx) => tr.dataset.index = String(idx));
}

function onEdit(i, key, val) { model[i][key] = val; }
function onAdd() { model.push({name:"", module:"", function:"", submenu:"", icon:"", enabled:true}); render(); }
function onAddAfter(i) { model.splice(i+1, 0, {name:"", module:"", function:"", submenu:"", icon:"", enabled:true}); render(); }
function onDelete(i) { model.splice(i,1); render(); }
function onDivider(i) { model.splice(i+1, 0, {name:"———", module:"", function:"", submenu:"", icon:"", enabled:false, type:"separator"}); render(); }

function onAddGlobal() {
  onAdd();
  selectRow(model.length - 1);
}

function onAddDividerGlobal() {
  const divider = {name:"———", module:"", function:"", submenu:"", icon:"", enabled:false, type:"separator"};
  if (selectedIndex == null) {
    model.push(divider);
  } else {
    model.splice(selectedIndex + 1, 0, divider);
  }
  render();
}

function onDeleteGlobal() {
  if (!model.length) return;
  if (selectedIndex == null) {
    model.pop();
    render();
    return;
  }
  model.splice(selectedIndex, 1);
  selectedIndex = null;
  render();
}

function onSave() {
  // ! Do NOT seed 'Toolbar Settings' here; it is hard-coded in Python and filtered server-side.
  // Defensive: strip it out if present
  model = model.filter(x => !(
    (x.name || "").toLowerCase() === "toolbar settings" &&
    x.module === "_Main_Toolbar.toolbar_editor" &&
    x.function === "edit_toolbar_json"
  ));

  const payload = JSON.stringify(model);
  pycmd("toolbar_editor:save:" + payload);
}

function hydrate(jsonStr) {
  try {
    model = JSON.parse(jsonStr);
  } catch(e) { model = []; }
  render();
}

function askRefresh() { pycmd("toolbar_editor:refresh"); }
