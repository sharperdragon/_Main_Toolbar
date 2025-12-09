# GUI Inspection Guide for Batch_FR

This document explains how to inspect and debug the user interface elements used in the **Batch Find & Replace (Batch_FR)** module. The module includes two types of dialogs:

- **HTML-based dialogs** (`BatchFRHtmlDialog`)
- **Qt widget-based dialogs** (`BatchFRRuleDialog`)

Because of limitations and stability issues with Qt WebEngine devtools on macOS + Qt6, the recommended approaches differ for each UI type.

---

## 1. Inspecting the HTML-Based Dialog (`BatchFRHtmlDialog`)

The HTML UI uses an `AnkiWebView` and loads external HTML, CSS, and JavaScript. For this type of UI, **do NOT rely on the built‑in Qt devtools** or the AnkiWebView Inspector add‑on, as they frequently freeze or crash on macOS with Qt6.

### ✔ Recommended Method: Chrome DevTools (Remote Debugging)

Alias in `~/.zshrc`:

```sh
alias anki-dev='QTWEBENGINE_REMOTE_DEBUGGING=8080 open -a Anki'
```

Then reload:

```sh
source ~/.zshrc
```

### Steps to Inspect

1. Open Anki using:
   ```sh
   anki-dev
   ```
2. Navigate to the Batch FR HTML dialog.
3. In Chrome, open:
   ```
   http://localhost:8080
   ```
4. Select the webview entry corresponding to the Batch FR window.
5. Chrome DevTools will open, allowing:
   - DOM inspection  
   - CSS editing  
   - JS console  
   - Network tools  
   - Breakpoints and script evaluation  

This provides the most reliable and responsive method of inspecting your UI.

---
