// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::sync::OnceLock;

/// Get global CSS.
pub fn global_css() -> &'static str {
    static CSS: OnceLock<String> = OnceLock::new();

    CSS.get_or_init(|| format!("{}{}{}", DARK_VARS, LIGHT_VARS, BASE_CSS))
}

const DARK_VARS: &str = r#"
:root {
  /* backgrounds */
  --em-bg-deep:      #0d1220;
  --em-bg-surface:   #1c2431;
  --em-bg-raised:    #374151;
  --em-bg-row:       #2a3347;

  /* accent */
  --em-accent:       #3628b0;
  --em-accent-hover: #4a38c8;
  --em-accent-dim:   rgba(54,40,176,0.4);

  /* interactive */
  --em-link:         #4da3ff;
  --em-focus:        #3399ff;

  /* text */
  --em-text-inv:     #ffffff;
  --em-text-1:       #f3f3f2;
  --em-text-2:       #d6d6d6;
  --em-text-3:       #9ba2ae;
  --em-text-4:       #6b7280;
  --em-text-5:       #b4b4b4;

  /* borders */
  --em-border:       #1c2431;
  --em-border-sub:   #374151;

  /* semantic */
  --em-success:      #00a36c;
  --em-danger:       #e34234;
  --em-warning:      #f59e0b;
  --em-green:        #22c55e;
}
"#;

const LIGHT_VARS: &str = r#"
.em-light {
  --em-bg-deep:      #f0f4f8;
  --em-bg-surface:   #ffffff;
  --em-bg-raised:    #f3f4f6;
  --em-bg-row:       #f9fafb;

  --em-accent:       #3628b0;
  --em-accent-hover: #4a38c8;
  --em-accent-dim:   rgba(54,40,176,0.12);

  --em-link:         #0070f3;
  --em-focus:        #0070f3;

  --em-text-inv:     #111827;
  --em-text-1:       #111827;
  --em-text-2:       #374151;
  --em-text-3:       #6b7280;
  --em-text-4:       #9ca3af;
  --em-text-5:       #6b7280;

  --em-border:       #e5e7eb;
  --em-border-sub:   #e5e7eb;

  --em-success:      #059669;
  --em-danger:       #dc2626;
  --em-warning:      #d97706;
  --em-green:        #059669;
}
"#;

const BASE_CSS: &str = r#"
* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  background: var(--em-bg-deep);
  color: var(--em-text-1);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  font-size: 15px;
  height: 100vh;
  overflow: hidden;
}

.app {
  display: flex;
  height: 100vh;
  overflow: hidden;
}

.sidebar {
  width: 200px;
  min-width: 200px;
  background: var(--em-bg-surface);
  display: flex;
  flex-direction: column;
  padding: 16px 8px;
  height: 100vh;
  overflow: hidden;
  transition: width 0.2s ease, min-width 0.2s ease;
}

.sidebar.collapsed {
  width: 56px;
  min-width: 56px;
}

.sidebar-title {
  font-size: 23px;
  font-weight: 700;
  color: var(--em-text-inv);
  text-align: center;
  padding: 8px 0 16px 0;
  overflow: hidden;
  white-space: nowrap;
}

.sidebar.collapsed .sidebar-title {
  font-size: 17px;
  padding: 8px 0 12px 0;
}

.sidebar-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 12px;
  border-radius: 6px;
  cursor: pointer;
  color: var(--em-text-2);
  font-size: 15px;
  text-decoration: none;
  border: none;
  background: none;
  width: 100%;
  text-align: left;
  transition: background 0.15s;
  white-space: nowrap;
  overflow: hidden;
}

.sidebar.collapsed .sidebar-item {
  justify-content: center;
  padding: 10px 0;
}

.sidebar.collapsed .sidebar-label {
  display: none;
}

.sidebar-item:hover  { background: var(--em-accent-dim); }
.sidebar-item.active { background: var(--em-accent); color: var(--em-link); }
.em-light .sidebar-item.active { background: rgba(54,40,176,0.14); color: #3628b0; font-weight: 600; }

.sidebar-icon {
  display: inline-flex;
  width: 22px;
  height: 22px;
  flex-shrink: 0;
}
.sidebar-icon svg { width: 22px; height: 22px; fill: currentColor; }

.sidebar-spacer { flex: 1; }

.sidebar-bottom {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 8px;
  padding: 8px;
}

.sidebar-toggle {
  background: var(--em-bg-raised);
  border: none;
  border-radius: 6px;
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: background 0.15s;
  flex-shrink: 0;
}
.sidebar-toggle:hover { background: var(--em-accent-dim); }
.sidebar-toggle svg   { width: 16px; height: 16px; fill: var(--em-text-3); }

.power-btn {
  background: var(--em-accent);
  border: none;
  border-radius: 50%;
  width: 40px;
  height: 40px;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: background 0.15s;
}
.power-btn.shutting-down { background: #d32f2f; }
.power-btn svg { width: 20px; height: 20px; fill: #fff; }

.main-content {
  flex: 1;
  background: var(--em-bg-deep);
  overflow-y: auto;
  height: 100vh;
}

.page {
  padding: 20px;
  display: flex;
  flex-direction: column;
  gap: 15px;
}

.page-title { display: flex; flex-direction: column; gap: 5px; }
.page-title h1 { font-size: 26px; color: var(--em-text-inv); font-weight: 600; }
.page-title p  { font-size: 17px; color: var(--em-text-2); }

.status-cards { display: flex; gap: 10px; padding: 5px; }

.status-card {
  flex: 1;
  background: var(--em-bg-surface);
  border-radius: 12px;
  padding: 10px;
  display: flex;
  align-items: center;
  gap: 10px;
  border: 1px solid var(--em-border);
}

.status-card-icon {
  width: 50px;
  height: 50px;
  background: var(--em-accent);
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
.status-card-icon svg { width: 28px; height: 28px; fill: #fff; }

.status-card-info { display: flex; flex-direction: column; gap: 2px; }
.status-card-title { font-size: 15px; color: var(--em-text-3); }
.status-card-value { font-size: 20px; color: var(--em-text-inv); font-weight: 200; }
.status-card-value-row { display: flex; align-items: center; gap: 6px; }
.status-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; display: inline-block; }

.bottom-panels { display: flex; gap: 10px; padding: 5px; }

.panel {
  flex: 1;
  background: var(--em-bg-surface);
  border-radius: 12px;
  border: 1px solid var(--em-border);
  padding: 10px;
  display: flex;
  flex-direction: column;
  gap: 5px;
}
.panel-title { font-size: 21px; color: var(--em-text-inv); text-align: center; margin-bottom: 6px; }
.panel-row   { display: flex; align-items: center; gap: 8px; }
.panel-label { color: var(--em-text-3); font-size: 13px; flex: 1; }
.panel-value { color: var(--em-text-3); font-size: 13px; }
.panel-value.enabled  { color: var(--em-success); }
.panel-value.disabled { color: var(--em-danger); }

.router-id-btn { background: none; border: none; color: var(--em-link); cursor: pointer; font-size: 13px; padding: 0; }

.bandwidth-card {
  background: var(--em-bg-surface);
  border-radius: 12px;
  border: 1px solid var(--em-border);
  padding: 16px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.bandwidth-card-title { font-size: 21px; color: var(--em-text-inv); text-align: center; }

.chart-container {
  background: var(--em-bg-raised);
  border-radius: 12px;
  height: 280px;
  overflow: hidden;
  position: relative;
}
.chart-container svg { width: 100%; height: 100%; }

.chart-x-axis {
  display: flex;
  justify-content: space-between;
  padding: 2px 0px 0 52px;
  font-size: 10px;
  color: var(--em-text-4);
}

.chart-legend { display: flex; justify-content: center; gap: 20px; }

.chart-legend-btn {
  background: none;
  border: none;
  cursor: pointer;
  font-size: 14px;
  padding: 0;
}

.chart-title {
  font-size:12px;
  font-weight:600;
  color:#9ba2ae;
  text-transform:uppercase;
  letter-spacing:0.05em;
  margin:12px 0 4px 5px;
}

.chart-label {
  padding-top: 5px;
  position:absolute;
  right:6px;
  font-size:10px;
  color:#9ba2ae;
  transform:translateY(50%);
  white-space:nowrap;
  line-height:1;
}

.time-buttons { display: flex; gap: 8px; }

.time-btn {
  padding: 6px 14px;
  border-radius: 6px;
  border: 1px solid var(--em-border-sub);
  background: var(--em-bg-raised);
  color: var(--em-text-2);
  cursor: pointer;
  font-size: 13px;
  transition: background 0.15s;
}
.time-btn.active { background: var(--em-accent); color: #fff; border-color: var(--em-accent); }

.bandwidth-controls { display: flex; align-items: center; gap: 20px; flex-wrap: wrap; }

.settings-card {
  background: var(--em-bg-surface);
  border-radius: 12px;
  border: 1px solid var(--em-border);
  display: flex;
  flex-direction: column;
  max-height: 750px;
}

.settings-container {
  padding: 16px;
  flex: 1;
  overflow-y: auto;
  min-height: 0;
}

.settings-footer {
  border-top: 1px solid var(--em-border-sub);
  padding: 10px 16px;
  display: flex;
  align-items: center;
  gap: 10px;
  flex-shrink: 0;
}

.settings-section { padding: 10px; display: flex; flex-direction: column; gap: 6px; margin-bottom: 10px; }
.settings-section-title {
  display: flex; justify-content: flex-start; align-items: center; gap: 14px;
  font-size: 17px; color: var(--em-text-inv); font-weight: 600; margin-bottom: 8px;
}

/* Two-column settings grid: label column auto-sizes to widest label in the section */
.sf-grid {
  display: grid;
  grid-template-columns: max-content auto;
  gap: 6px 12px;
  align-items: center;
}
.sf-label { font-size: 13px; color: var(--em-text-3); }
.sf-grid input[type="text"] { width: auto; max-width: 180px; }
.sf-input-short { max-width: 88px !important; }
.sf-input-wide  { max-width: 300px !important; }

/* Paired sub-fields (e.g. length + count on one row) */
.sf-pair { display: flex; align-items: center; gap: 8px; }
.sf-pair-label { font-size: 12px; color: var(--em-text-4); }
.sf-pair input[type="text"] { width: 64px; }

/* Dim body rows when the section is disabled */
.sf-disabled .sf-grid,
.sf-disabled .sf-ip-cols { opacity: 0.4; pointer-events: none; }

/* Side-by-side IPv4 / IPv6 panels inside a transport section */
.sf-ip-cols { display: flex; gap: 12px; width: fit-content; }
.sf-ip-col {
  width: fit-content;
  background: var(--em-bg-raised);
  border-radius: 8px;
  padding: 10px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.sf-ip-col-title {
  font-size: 11px;
  font-weight: 600;
  color: var(--em-text-2);
  text-transform: uppercase;
  letter-spacing: 0.06em;
}
.sf-ip-col .sf-grid { margin-top: 0; }

label.field-label { font-size: 13px; color: var(--em-text-3); }

input[type="text"],
input[type="number"],
textarea {
  background: var(--em-bg-raised);
  border: 1px solid var(--em-border);
  border-radius: 6px;
  color: var(--em-text-1);
  font-size: 13px;
  padding: 8px 10px;
  width: 100%;
  outline: none;
}
input[type="text"]::placeholder,
textarea::placeholder { color: var(--em-text-3); }
input[type="text"]:focus,
textarea:focus { border-color: var(--em-focus); }

.checkbox-row {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
}
.checkbox-row input[type="checkbox"] {
  -webkit-appearance: none;
  appearance: none;
  width: 18px;
  height: 18px;
  min-width: 18px;
  border: 2px solid var(--em-border);
  border-radius: 4px;
  background: var(--em-bg-raised);
  cursor: pointer;
  flex-shrink: 0;
  display: grid;
  place-content: center;
  transition: background 0.12s, border-color 0.12s;
}
.checkbox-row input[type="checkbox"]::before {
  content: '';
  width: 10px;
  height: 10px;
  transform: scale(0);
  transition: transform 0.1s;
  background: #fff;
  clip-path: polygon(14% 44%, 0 65%, 50% 100%, 100% 16%, 80% 0%, 43% 62%);
}
.checkbox-row input[type="checkbox"]:checked {
  background: var(--em-focus);
  border-color: var(--em-focus);
}
.checkbox-row input[type="checkbox"]:checked::before {
  transform: scale(1);
}
.checkbox-row span {
  font-size: 13px;
  color: var(--em-text-3);
  }

.tabs {
  display: flex;
  gap: 0;
  border-bottom: 1px solid var(--em-border-sub);
  margin-bottom: 12px;
}

.tab-btn {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 14px;
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  cursor: pointer;
  color: var(--em-text-5);
  font-size: 14px;
  transition: color 0.15s, border-color 0.15s;
}
.tab-btn svg { width: 18px; height: 18px; fill: currentColor; }
.tab-btn.active { color: var(--em-focus); border-bottom-color: var(--em-focus); }

.btn {
  padding: 8px 18px;
  border-radius: 6px;
  border: none;
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  transition: background 0.15s;
}
.btn-primary            { background: var(--em-accent); color: #fff; }
.btn-primary:hover      { background: var(--em-accent-hover); }
.btn-secondary          { background: var(--em-bg-raised); color: var(--em-text-2); }
.btn-secondary:hover    { background: #4b5563; }
.btn-danger             { background: var(--em-danger); color: #fff; }
.btn-icon {
  background: none; border: none; cursor: pointer; padding: 3px;
  display: inline-flex; align-items: center; color: var(--em-text-3);
}
.btn-icon:hover { color: var(--em-text-inv); }
.btn-icon svg { width: 18px; height: 18px; fill: currentColor; }

.status-ok    { color: var(--em-success); font-size: 13px; padding: 6px 0; }
.status-error { color: var(--em-danger);  font-size: 13px; padding: 6px 0; }

.input-error {
  border-color: var(--em-danger) !important;
  background: rgba(227,66,52,0.06) !important;
}
.form-row {
  display: flex;
  gap: 10px;
  align-items: flex-start;
  margin-bottom: 4px;
}
.button-row {
  display: flex;
  gap: 8px;
  margin-top: 10px;
}

.search-bar {
  display: flex;
  align-items: center;
  background: var(--em-bg-raised);
  border: 1px solid var(--em-border);
  border-radius: 6px;
  padding: 0 10px;
  gap: 6px;
}
.search-bar svg   { width: 16px; height: 16px; fill: var(--em-text-3); flex-shrink: 0; }
.search-bar input {
  background: none; border: none; flex: 1;
  color: var(--em-text-1); font-size: 13px; outline: none; padding: 8px 0;
}
.search-bar input::placeholder { color: var(--em-text-3); }

.table-header {
  display: flex;
  padding: 4px 0;
  border-bottom: 1px solid var(--em-border-sub);
  font-size: 13px;
  color: var(--em-text-3);
  font-weight: 600;
}
.table-row {
  display: flex;
  padding: 6px 0;
  border-bottom: 1px solid var(--em-bg-row);
  align-items: center;
  font-size: 13px;
  color: var(--em-text-3);
}
.table-row:last-child { border-bottom: none; }
.col-name     { flex: 2; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.col-port     { flex: 1; }
.col-addr     { flex: 3; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.col-dest     { flex: 3; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.col-action   { flex: 1; display: flex; gap: 4px; }
.col-hostname { flex: 2; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.col-value    { flex: 4; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.table-scroll { max-height: 670px; overflow-y: auto; }

.empty-state {
  display: flex; flex-direction: column;
  align-items: center; justify-content: center;
  padding: 32px 16px; gap: 8px;
  color: var(--em-text-4); text-align: center;
}
.empty-state-icon     { font-size: 28px; opacity: 0.5; }
.empty-state-title    { font-size: 14px; color: var(--em-text-3); font-weight: 500; }
.empty-state-subtitle { font-size: 12px; color: var(--em-text-4); }

.confirm-delete-row { display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--em-danger); }
.btn-confirm-yes {
  background: var(--em-danger);
  color: #fff;
  border: none;
  border-radius: 4px;
  padding: 2px 8px;
  font-size: 12px;
  cursor: pointer;
}
.btn-confirm-no  {
  background: var(--em-bg-raised);
  color: var(--em-text-2);
  border: none;
  border-radius: 4px;
  padding: 2px 8px;
  font-size: 12px;
  cursor: pointer;
}

.card {
  background: var(--em-bg-surface);
  border-radius: 12px;
  border: 1px solid var(--em-border);
  padding: 16px;
}
.service-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
  display: inline-block;
  margin-right: 4px;
}
.service-dot-running {
  background: var(--em-green);
}

.toast-container {
  position: fixed; bottom: 20px; right: 20px;
  display: flex; flex-direction: column; gap: 8px;
  z-index: 1000; pointer-events: none;
}
.toast {
  background: var(--em-bg-surface);
  border: 1px solid var(--em-border-sub);
  border-left: 3px solid var(--em-accent);
  border-radius: 6px;
  padding: 10px 16px;
  font-size: 13px;
  color: var(--em-text-1);
  box-shadow: 0 4px 12px rgba(0,0,0,0.4);
  min-width: 200px; max-width: 320px;
}

.modal-overlay {
  position: fixed; inset: 0;
  background: rgba(0,0,0,0.55);
  display: flex; align-items: center; justify-content: center;
  z-index: 500;
}
.modal {
  background: var(--em-bg-surface);
  border: 1px solid var(--em-border-sub);
  border-radius: 12px;
  padding: 24px;
  min-width: 500px; max-width: 600px;
  display: flex; flex-direction: column; gap: 16px;
}
.modal-title { font-size: 18px; color: var(--em-text-inv); font-weight: 600; }
.modal-footer { display: flex; gap: 8px; justify-content: flex-end; }
"#;

/// Script to remove right-click menu from desktop view.
#[cfg(feature = "dioxus")]
pub const DESKTOP_HEAD: &str = r#"<script>document.addEventListener('contextmenu',function(e){e.preventDefault();},true);</script>"#;
