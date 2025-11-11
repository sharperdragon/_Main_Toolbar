# Tag Renaming Rules — Quick Reference

**Quick Reference — What to Escape (in patterns)**
When matching literal text in the **pattern**, escape these regex characters:

| Symbol | Write in pattern (JSON) |
|---|---|
| `.` | `\\.` |
| `^` | `\\^` |
| `$` | `\\$` |
| `*` | `\\*` |
| `+` | `\\+` |
| `?` | `\\?` |
| `(` | `\\(` |
| `)` | `\\)` |
| `[` | `\\[` |
| `]` | `\\]` |
| `{` | `\\{` |
| `}` | `\\}` |
| `|` | `\\|` |
| `\\` | `\\\\` |

**Inside a character class `[ ... ]`** also escape:
- `]` as `\\]`
- `-` as `\\-` (unless first or last)
- leading `^` as `\\^`

**Captures in replacements:**
- Use `$1`, `$2`, etc. in JSON → loader converts to `\\1`, `\\2` for Python.
- **Never** write `\\1` directly in JSON.

This guide explains how to write rules in the `rules` folder to rename Anki tags safely and consistently.

---
## ✅ Allowed File Types
- `.json` — preferred for regex and complex rules
- `.csv` — simple literal `old,new` rows
- Avoid backups/temp files (`.bak`, `~`, hidden dotfiles) — the tool ignores them

> **Load order:** CSV first, then JSON. If the same `old` appears twice, the **first** entry wins.

---
## ✅ Two Types of Rules

### 1. Literal Rules (CSV or JSON)
Use when the old tag matches exactly.

**CSV example:**
```
old,new
#AK_Step1_v12,#Zank::Step1_v12
```

**JSON example:**
```
{ "old": "#AK_Step1_v12", "new": "#Zank::Step1_v12" }
```
- Moves all children automatically: `#AK_Step1_v12::Heart` → `#Zank::Step1_v12::Heart`

---
### 2. Regex Rules (JSON only)
Use for patterns, captures, or groups.

**Basic json format:**
```
{ "pattern": "#AK_(Step1_v12)", "replacement": "#Zank::$1" }
```
- `$1`, `$2` etc. represent capture groups.
- The loader automatically converts `$1` → `\1` for Python.
- **Never** try to write Python regex escapes directly (`\1`) in JSON — just use `$1`.

---
## ✅ How to Escape Special Characters in Patterns
Regex characters with special meaning: `. ^ $ * + ? ( ) [ ] { } |`

If you want them to be **literal text**, you must escape them with a backslash:

| Literal you want | ✅ Correct regex pattern | ❌ Wrong |
|------------------|--------------------------|--------|
| `^Formula`        | `\^Formula`              | `^Formula` (anchors at start of full tag) |
| `(` character     | `\(`                     | `(`     |
| `)` character     | `\)`                     | `)`     |
| `[` or `]`        | `\[` / `\]`              | `[` / `]` |

**Example rule capturing literal `^Formula`:**
```
{ "pattern": "#AK_Other::Card_Features::(\\^Formula)",
  "replacement": "#Zank::Card_Features::$1" }
```

## ✅ Pattern vs Replacement Escaping
Patterns and replacements follow different rules:

| Symbol | In **pattern** (left side) | In **replacement** (right side) |
|--------|-----------------------------|----------------------------------|
| `. ^ $ * + ? ( ) [ ] { } | \` | Special regex metacharacters. Escape them when literal (e.g., `\^Formula`, `\(`, `\[`). | Mostly literal. Only backslashes and `$` + digit matter. |
| `#` and `:` | Literal — safe as-is under current settings. `::` is just two literal colons. | Literal — safe as-is. |
| `$1`, `$2`, etc. | Captures only in replacement. Do **not** use in patterns. | Use `$1`, `$2`. Loader converts to `\1`, `\2` for Python automatically. |
| Literal `$` before a digit (you want to output `$1` literally) | `$` is literal, but `$1` means capture. | Escape as `\$1` in JSON, so loader won’t turn it into a capture. |
| Literal backslash in output | `\\` in pattern matches a literal backslash. | Write `\\` in JSON so runtime output has one `\`. |

### ✅ Practical Rules
- If you are matching **literal text in the pattern**, escape regex metacharacters.
- If you are **outputting** text in the replacement, only escape:
  - backslashes (write `\\` in JSON)
  - `$` when followed by a digit and you *don’t* want a capture (write `\\$1`).
- `#` and `:` are normal characters on both sides.

---
## ✅ Segment Boundaries
To ensure the capture ends at the segment boundary and not just anywhere:
```
(?=$|::)
```
Example:
```
"#AK_Other::Card_Features::(\\^Formula)(?=$|::)"
```

---
## ✅ Child-Tail Patterns and Prefix Matching
If a pattern ends with a child tail like `::(.*)$`, the prefix preflight removes the tail **only for matching prefixes**.
**Replacements stay untouched in safe mode** — `$1` and literal `#` are preserved.

Example:
```
{ "pattern": "(#OME)_banner::(Clinical)", "replacement": "$1::$2" }
```
Produces:
```
#OME_banner::Clinical → #OME::Clinical
```

---
## ✅ Literal `#` in Replacements
Valid:
```
{ "pattern": "#AK_(Step2_v12)", "replacement": "#Zank::#$1" }
```
→ `#AK_Step2_v12` becomes `#Zank::#Step2_v12`

---
## ❌ Common Mistakes
| Mistake | Why it fails | Fix |
|---------|--------------|-----|
| `(^Formula)` | `^` anchors start of entire tag, not segment | `(\\^Formula)` |
| `Clinical$`  | `$` anchors end of full tag, fails in middle | remove `$` unless terminal |
| Duplicate separators `::::` | trailing `::` inside capture + replacement adds another `::` | remove trailing `::` from capture |

---
## ✅ Good Examples
```
{ "pattern": "#(PANCE)", "replacement": "#Zank::$1" }
{ "pattern": "(#OME)_banner::(Clinical)", "replacement": "$1::$2" }
{ "pattern": "#AK_Other::Card_Features::(\\^Formula)", "replacement": "#Zank::Card_Features::$1" }
```

---
## ✅ When the Rule Will Renovate Children
- Literal mapping: always moves children.
- Regex mapping: moving the **parent** moves all children with it.
- You do **not** need to write child rules unless the child’s text itself changes.

---
## ✅ Testing Tips
- After adding rules: check 3–5 tags expected to move.
- If nothing changes, rule likely never matched: check escapes, stray `$`, or anchors.
- Look at the Regex Debug report in your output folder.

---
## ✅ Summary
- Use JSON for regex and captures.
- Escape special characters like `^ ( ) [ ]` when literal.
- Use `$1`, `$2` — loader will transform internally.
- Safe mode preserves replacements; nothing is stripped.
- Confirm with a few real notes.