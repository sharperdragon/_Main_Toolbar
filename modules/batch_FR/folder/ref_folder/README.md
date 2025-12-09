## 🧠 How It Works

### 1. Configuration
Runtime behavior is controlled through `config.json`:

```json
{
  "dry_run": true,
  "report_path": "/Users/claytongoddard/FR_simple/reports",
  "rules_path": "/Users/claytongoddard/FR_simple/rules",
  "remove_path": "/Users/claytongoddard/FR_simple/remove_rules.txt",
  "fields_all": ["Text","Extra","Extra2","Extra3","Extra4","Extra5","Extra6","Extra7","Front","Back","Display"],
  "log_mode": "diff",
  "include_unchanged": false,
  "delete_chars": { "max_chars": 0, "count_spaces": true }
}
```

| Key | Description |
|-----|-------------|
| `dry_run` | If `true`, runs in preview mode — no changes applied. |
| `report_path` | Directory where reports are saved (DRY runs go to `report_path/DRYRUN/`). |
| `rules_path` | File or folder containing rules (`*rule.json`, `*rules.json`, `*_rules.txt`, `.csv`). |
| `remove_path` | Optional path for full deletion patterns (field-remove pipeline). |
| `fields_all` | Fallback list of note fields for rules that use `["ALL"]` or omit `fields`. |
| `log_mode` | `"diff"` shows before/after comparisons; `"summary"` prints compact lines. |
| `include_unchanged` | Include untouched notes in the report. |
| `delete_chars` | Default deletion guard when a rule omits its own: `{ "max_chars": N, "count_spaces": true }`. |

---

### 2. Rule Structure

Rules define **what to find**, **what to replace**, and **where**.  
They can live in `.json`, `.txt`, or `.csv` files under your `rules/` directory.

#### **Rule Fields Explained**

Each rule determines which notes to search, what text to find, and how to replace it.  
Below are all possible fields and their valid values.

| Field | Type | Required | Notes |
|---|---|---|---|
| `query` | string \| array | ❌ | If omitted and `pattern` is present, the engine builds a query (Tags → `tag:`; else global). Arrays are AND-ed. |
| `exclude_query` | array | ❌ | Each entry is appended as a negative (`-()`) filter. |
| `pattern` | string \| array | ✅ | Text or regex. If array, engine expands into one sub‑rule per pattern. |
| `replacement` | string | ✅ | `$1`, `$2`, … capture groups; use `$$` for a literal `$`. |
| `regex` | boolean | ❌ | Default `true`. If `false`, literal find/replace. |
| `flags` | string | ❌ | Combine `i`, `m`, `s`, `x`. Default `"m"`. |
| `fields` | array | ❌ | `["ALL"]` uses `fields_all` from config; otherwise list explicit fields. |
| `anchored` | boolean | ❌ | If `true`, engine builds a fielded OR query across `fields_all`. |
| `loop` | boolean | ❌ | Repeat until no change (capped by `MAX_RULE_LOOP_ITERS`). |
| `delete_chars` | object \| integer | ❌ | Guard deletions. Object `{ "max_chars": n, "count_spaces": true }`. Integer = legacy. `-1` = unlimited. |

> Legacy `max_delete_chars` is still accepted, but normalized to `delete_chars.max_chars`.

---

**`query`**  
Type: `string`  
Defines the **Anki search query** that selects notes to modify.  
You can use all Anki Browser search operators:
- `deck:` — limit to a deck  
- `note:` — limit to a note type  
- `tag:` — include a tag  
- `-tag:` — exclude a tag  
- `re:` — regex search mode  
- Quoted strings `" "` — exact phrase match  
If blank (`""`), the rule applies to all notes.

---

**`exclude_query`**  
Type: `array` of strings  
Optional. Each entry adds a **negative search filter** to exclude specific notes.  
Example:
```json
"exclude_query": ["tag:suspend", "class=\"temp\""]
```
Anki search equivalent:
```
-"tag:suspend" -"class=\"temp\""
```

---

**`pattern`**  
Type: `string`  
Defines the text or regex pattern to locate inside target fields.  
If `regex` is `true`, the syntax follows Python’s `re` module —  
meaning all backslashes must be escaped (`\\d`, `\\{`, etc.).

Example:
```json
"pattern": "(\\{\\{c\\d)::([^:\\}]+?)::([^\\}]+?)\\}\\}"
```

### 🔐 Critical Escaping & Syntax

| You want… | In JSON | Regex sees | Notes |
|------------|----------|-------------|--------|
| `\d` | `\\d` | `\d` | JSON eats one backslash. |
| Literal backslash | `\\` | `\` |  |
| Literal `{` or `}` | `\\{` / `\\}` | `{` / `}` | Avoid JSON/regex confusion. |
| Literal `(` or `)` | `\\(` / `\\)` | `(` / `)` | Non‑grouping literal parens. |
| Literal `$` in replacement | `$$` | `$` | `$1` is capture 1; `$$` = literal. |

**Anki query quoting (very important)**  
Always quote the **entire filter** (field/tag + `re:` + pattern):

- ✅ `"Front:re:\\(term\\)"`
- ✅ `("Front:re:foo" OR "Back:re:foo")`
- ❌ `Front:"re:\(term\)"` (quotes only around `re:` — wrong)

---

**`replacement`**  
Type: `string`  
Text that replaces every `pattern` match.  
Supports numbered capture groups from regex (`$1`, `$2`, etc.).  
To insert a literal `$`, use `$$`.

Example:
```json
"replacement": "$1::$2::$3 / $4}}"
```
Converts `{{c1::term/term}}` → `{{c1::term / term}}`.

### 🧯 Deletion Guard (`delete_chars`)

Controls how many **visible** characters a rule may delete.

- Object form: `{ "max_chars": 7, "count_spaces": true }`
- Integer form: `7` (legacy; equals the object with `count_spaces: true`)
- `-1` → unlimited

The engine compares visible lengths (HTML stripped + entities unescaped).  
If exceeded, the rule is skipped and logged, e.g.:
```
⚠️ Skipped rule '/…/': deleted 15 visible characters (limit: 7; spaces=yes)
```

---

**`regex`**  
Type: `boolean`  
Controls how `pattern` is interpreted.  
Valid values:
- `true` → Treat pattern as a **regular expression**.  
- `false` → Treat pattern as **literal text**.

---

**`flags`**  
Type: `string`  
Optional regex modifiers that adjust how patterns are matched.  
Multiple can be combined (e.g., `"ims"`).  
FR_simple uses **Python’s `re` module**, while Anki uses **Qt’s QRegularExpression** (ECMAScript-style regex).  
This means some flags act differently or are always on/off in Anki.

| Flag | Meaning | Default |
|------|---------|---------|
| `i` | Ignore case | Off |
| `m` | `^`/`$` match per line | On (`"m"`) |
| `s` | Dot matches newline | Off |
| `x` | Verbose mode | Off |

> Use `"flags": "ms"` when your pattern must span newlines.

**Usage Example**
```json
{
  "pattern": "<div>.*?</div>",
  "replacement": "<div class=\"match\">\\g<0></div>",
  "regex": true,
  "flags": "is"
}

---

**`fields`**  
Type: `array` of strings  
Specifies which note fields the rule affects.  
Each name must match an existing field in your notes or those listed under `fields_all` in `config.json`.  
If left blank, the rule applies to all fields.

Example:
```json
"fields": ["Text", "Extra"]
```

---

**Summary of limited options**

| Field | Valid Values |
|--------|---------------|
| `regex` | `true`, `false` |
| `flags` | `i`, `m`, `s`, `x` (any combination) |
| `fields` | Any subset of those listed in `config.json → fields_all` |

---

### 3. Rule File Types

You can split rules into multiple files:

```
rules/
 ├── base_rules.json
 ├── html_cleanup_rules.txt
 ├── formatting_rules.json
 └── remove_rules.txt
```

The program automatically loads every file matching `*_rules.json` or `*_rules.txt`.

#### Example TXT Rule File (CSV style)

```txt
pattern,replacement,regex,fields
^\s*(<br>)+\s*,,
\s*(<br>)+\s*$,,,
```

If you need regex, add a `regex` column with `true`, and you can also add `flags` (e.g., `i`, `m`, `s`, `x`).

---

### 4. Running the Script

Run `_find_replace.py` directly in VS Code (no terminal needed):

```python
python3 _find_replace.py
```

- The log prints the **exact** query sent to Anki (including exclusions), e.g.:
  ```
  Found 744 notes for query: ("Front:re:\\(e\\.g\\.,* ([^\\)]+?)\\)") -"tag:suspend"
  ```
- DRY runs write to `report_path/DRYRUN/<HH-MM_MM-DD>_ACFR_report.txt`.
- Apply runs also create NID logs in `LOGS_DIR/NID/<HH-MM_MM-DD>_NIDs.txt`.
## 🧠 What Runs What (Functions Map)

**Find + Replace (in‑memory text ops)**
- `utils.main_utils.normalize_rule(rule, defaults)` — expands arrays, applies defaults; sets `_del_max`, `_del_count_spaces`.
- `utils.main_utils.subn_until_stable(text, regex, repl, flags)` — repeat `re.subn` until stable.
- `_find_replace.py.apply_rules_to_text(text, rules)` — applies each rule; enforces deletion guard; handles `loop`.
- `utils.logic_utils.deletion_exceeds_limit(before, after, max_chars, *, count_spaces)` — unified guard check.
- `utils.utils_helper.visible_len(text, count_spaces)` — visible char length after HTML strip + unescape.

**Query building / scrubbing**
- `utils.main_utils.build_field_or_query(pattern, fields)` — fielded OR query.
- `utils.main_utils._append_exclusions(query, exclude_list)` — appends `-()` exclusions safely.
- `_find_replace.py._build_field_or_query_for_remove(pattern, fields)` — OR across fields for remove flow.

**Talking to Anki (AnkiConnect)**
- `_find_replace.py.invoke("findNotes", query=...)`
- `_find_replace.py.invoke("notesInfo", notes=[...])`
- `_find_replace.py.invoke("updateNoteFields", note={id, fields})`


---

## 🧾 Output Example

```
AnkiConnect Multi Find+Replace Report
Rules path: /Users/.../rules
Rules files:
  - base_rules.json (12 rules)
  - remove_rules.txt (2 rules)

Dry-run: True
Modified notes: 57 / 423 total
Unchanged: 366
```

Each modified note includes a color-coded diff showing before and after replacements.

---

### ⚙️ Compatibility

| Component | Minimum Version | Notes |
|------------|-----------------|-------|
| **Python** | 3.9+ | Required for f-strings and pathlib. |
| **Anki** | 2.1.60+ | Must have [AnkiConnect](https://foosoft.net/projects/anki-connect/) enabled. |
| **Regex Engine** | Python `re` | Different from Anki’s built-in ECMAScript regex. |
| **Platform** | macOS / Windows / Linux | Tested primarily on macOS 15+. |

---

## 🧰 Rule Schema Reference

`rules_schema.json` defines the expected structure:

```json
{
  "query": "",
  "exclude_query": [],
  "pattern": "",
  "replacement": "",
  "regex": true,
  "flags": "",
  "fields": []
}
```

Use this as a guide when creating new JSON rule sets.

---

## 🔐 Escaping Rules (JSON vs. Regex vs. Anki)

### What needs escaping in JSON rule files
JSON strings must escape characters that either:
- conflict with JSON itself, or
- are part of your **regex**.

**General JSON escapes**
- Double quotes inside strings → `\"`
- Backslashes → `\\` (so regex like `\d` becomes `"\\d"`)
- Newlines in strings → `\n`
- Tabs in strings → `\t`

**Regex-specific escapes**
- Literal curly braces → `\\{` and `\\}`
- Literal parentheses → `\\(` and `\\)`
- Literal square brackets → `\\[` and `\\]`
- Literal plus/asterisk/question → prefix with `\\+`, `\\*`, `\\?` if you mean the literal character
- HTML angle brackets (literal) are fine as `<` and `>`, but if you combine with regex anchors `^` or `$`, those anchors remain unescaped.

**Replacement string escapes**
- To insert a **literal dollar sign** (because `$1`, `$2`, … are capture groups), use `$$`.
- Backslashes also need escaping in JSON: write `\\` to produce a single backslash in the result.
- If you need literal braces in the replacement, write them normally `{` `}` (only the JSON quoting rules apply).

**Examples**
- Regex digit class in JSON:  
  Pattern: `\\d+`  
  Meaning: one or more digits (`\d+`)
- Literal `{` in JSON pattern:  
  Pattern: `\\{`  
  Meaning: a literal `{`
- Matching a double-escaped backslash in text:  
  Pattern: `\\`

---

### 🔍 Quick Reference — Escapes and Flags

| Context | Example | Notes |
|----------|----------|-------|
| JSON | `\\d` | Double escaping required in JSON strings. |
| Regex | `\d` | Standard Python regex escape. |
| Replacement | `$$` | Inserts a literal `$`. |
| Flags | `"imsx"` | Valid Python regex flags for FR_simple. |
| Anki Inline Flags | `(?i)`, `(?s)` | Only available inline inside regex patterns. |

---

## 🔁 How this compares to native Anki search & replace

### Queries
- **This tool**: `query` is passed to Anki’s Browser search **as-is**. You can use all of Anki’s operators (e.g., `deck:`, `note:`, `tag:`, quotes, `-term` for exclusion, and `re:` patterns).  
- **Enhancement**: `exclude_query` lets you list additional exclusions as an **array**. The engine appends these as negatives (e.g., `-("class=\"flex-L\"")`) when running the search.
- **Native Anki**: you manually type the whole search in the Browser (single text box). No structured `exclude_query` list.

### Find & Replace engine
- **This tool**: `pattern` uses the Python-style regex engine with optional `flags` (`i`, `m`, `s`, `x`).  
  - **Capture groups in replacement**: use `$1`, `$2`, … (the tool preserves this style so your rules stay concise).  
  - Multi-file rules with per-rule `fields`, plus directory-wide loading of `*_rules.json` and `*_rules.txt`.
- **Native Anki**: the Browser’s *Find and Replace* supports regex but does **not** expose flags like `m`/`s`/`x` in the UI; you must fit everything into the one dialog.  
  - **Capture groups** commonly use `\1`, `\2`, … in replacement.  
  - No concept of multi-file modular rule packs.

### Practical equivalence

Here’s how each part of a JSON rule aligns with Anki’s native *Find & Replace* behavior:

| Rule Component | JSON Example | Native Anki Equivalent |
|----------------|---------------|-------------------------|
| **Search scope (`query`)** | `"query": "deck:Step1 note:Basic tag:neuro"` | Typed directly in Anki’s *Search Bar* → `deck:Step1 note:Basic tag:neuro` |
| **Exclusion (`exclude_query`)** | `"exclude_query": ["tag:suspend", "class=\"temp\""]` | Add a negative search manually → `-tag:suspend -"class=\"temp\""` |
| **Pattern (`pattern`)** | `"pattern": "(\\{\\{c\\d)::([^:\\}]+?)::([^\\}]+?[^\\s<])/([^\\s][^\\}]+?)\\}\\}"` | Enter this regex into Anki’s *Find* field (with regex mode checked):<br>`(\{\{c\d)::([^:\}]+?)::([^\}]+?[^\s<])/([^\s][^\}]+?)\}\}` |
| **Replacement (`replacement`)** | `"replacement": "$1::$2::$3 / $4}}"` | In Anki’s *Replace* field: `$1::$2::$3 / $4}}` |
| **Regex mode (`regex`)** | `"regex": true` | Check “Use regular expressions” in Anki’s dialog |
| **Regex flags (`flags`)** | `"flags": "m"` | Not available in Anki’s UI; Anki’s regex mode always assumes single-line behavior |
| **Fields (`fields`)** | `"fields": ["Text", "Extra"]` | Select “Fields → Text, Extra” manually in Anki’s UI |

---

#### Full Rule Example Comparison

**JSON Rule**
```json
{
  "query": "deck:Step1 note:Basic tag:micro",
  "exclude_query": ["tag:suspend", "class=\"temp\""],
  "pattern": "(\\{\\{c\\d)::([^:\\}]+?)::([^\\}]+?[^\\s<])/([^\\s][^\\}]+?)\\}\\}",
  "replacement": "$1::$2::$3 / $4}}",
  "regex": true,
  "flags": "m",
  "fields": ["Text"]
}
```

**Equivalent Native Anki Operation**
```
1. Search Bar:  deck:Step1 note:Basic tag:micro -tag:suspend -"class=\"temp\""
2. Enable “Use Regular Expressions”.
3. Find:        (\{\{c\d)::([^:\}]+?)::([^\}]+?[^\s<])/([^\s][^\}]+?)\}\}
4. Replace:     $1::$2::$3 / $4}}
5. Target Fields: Text
```

> 🔍 **Tip:** JSON rules support features Anki doesn’t — like multiple exclude terms, `flags`, and file-based batching.  
> That means one JSON rule can automate what might take multiple manual search-and-replace steps in Anki.

---

## 🧼 Example Use Cases

- Normalize `<br>` tags and HTML spacing.
- Add missing spaces in cloze deletions (`{{c1::term/term}} → {{c1::term / term}}`).
- Clean leftover formatting tags like `<span class="fw-350">`.
- Exclude specific tags or sections with `exclude_query`.

---

## 🧪 Common Regex Patterns

A few ready-to-use examples for frequent text cleanup tasks.

| Purpose | Pattern | Replacement |
|----------|----------|-------------|
| Add space between slashes in clozes | `(\\{\\{c\\d)::([^:\\}]+?)::([^\\}]+?[^\\s<])/([^\\s][^\\}]+?)\\}\\}` | `$1::$2::$3 / $4}}` |
| Remove extra `<br>` lines | `^\\s*(<br>)+\\s*` | (empty string) |
| Normalize multiple spaces | `\\s{2,}` | ` ` |
| Remove empty `<span>` elements | `<span[^>]*></span>` | (empty string) |
| Convert `<b>text</b>` to strong tag | `<b>(.*?)</b>` | `<strong>$1</strong>` |

> 🧠 **Tip:** Test these on [regex101.com](https://regex101.com/) using the **Python flavor** before adding to your rules.
------
---

## 🧮 Batch Execution Behavior

- FR_simple automatically loads **all rule files** matching `*_rules.json` or `*_rules.txt` inside the `rules/` folder.  
- Files are executed **in alphabetical order**.  
- Later rules can modify text already changed by earlier ones.  
  - Example: `base_rules.json` runs before `html_cleanup_rules.txt`.  
- To control order, prefix filenames numerically (e.g., `01_base_rules.json`, `02_cleanup_rules.txt`).

> 💡 **Tip:** Keep formatting or cleanup rules last, so earlier replacements don’t get reverted by HTML normalizers.

---

## 🧩 Notes

- `_find_replace.py` automatically handles multiple rules files in a directory.
- Supports AnkiConnect queries for precise targeting.
- Backward-compatible with older single-file rule setups.
- If `dry_run` is disabled, edits are written directly through AnkiConnect API calls.

---

## 🧩 Troubleshooting & Validation

Common issues and how to resolve them quickly.

| Problem | Likely Cause | Fix |
|----------|---------------|-----|
| **No notes modified** | Query didn’t match anything | Verify your `query` and `fields_all` include the target notes/fields. |
| **Regex fails to run** | Pattern invalid or unescaped | Test on [regex101.com](https://regex101.com/) with Python mode. |
| **Empty replacements** | Wrong capture groups | Check numbering (`$1`, `$2`, …). |
| **Unexpected HTML left behind** | Pattern too narrow | Broaden your regex with `.*?` or `[^>]` classes. |
| **“Bad JSON” error** | Missing comma or quote | Validate your rule file using an online JSON validator. |
| **Performance lag** | Too many rules in one file | Split rules into multiple smaller `_rules.json` files. |

> 🧩 **Tip:** Run with `"dry_run": true` in `config.json` to safely preview all replacements before committing.
------


## 📁 Project Structure

```
FR_simple/
├── _find_replace.py          # Main processing script
├── config.json               # Runtime configuration
├── README.md                 # Documentation
├── rules/                    # Directory for all rule files
│   ├── base_rules.json       # Example JSON rule set
│   ├── remove_rules.txt      # Example TXT rule set
│   ├── html_cleanup_rules.txt
│   └── formatting_rules.json
└── assets/                   # (optional) For backups or reports
```

## 📂 File Summary

| File | Purpose |
|------|----------|
| `_find_replace.py` | Main processing engine. |
| `config.json` | Runtime configuration and paths. |
| `rules_schema.json` | Defines structure for all rules. |
| `base_rules.json` | Default rule set for formatting cleanup. |
| `remove_rules.txt` | Simple find/remove rules (CSV syntax). |
