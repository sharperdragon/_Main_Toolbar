# pyright: reportMissingImports=false
# mypy: disable_error_code=import

import os
import re
import sqlite3
from aqt import mw
from aqt.utils import showInfo

# --- CONFIG ---
# If enabled, only scan notes that have the specific tag (exact match, normalized by Anki)
TAG_FILTER_ENABLED = True
TAG_NAME = "missing-media"  # The tag to filter notes by when TAG_FILTER_ENABLED is True

# Media extensions to look for inside note fields
MEDIA_EXTENSIONS = {".png", ".jpg", ".jpeg", ".svg", ".gif", ".mp3", ".mp4"}



def write_missing_file():
    from urllib.parse import unquote, urlparse

    def normalize_refs(text, extensions):
        """Extract media basenames from HTML/text safely.
        - Grabs src="...".
        - URL-decodes (%20 -> space).
        - Strips query/hash.
        - Returns only basenames that end with a known extension.
        """
        refs = set()

        # Pull out src="...".
        for m in re.findall(r'(?i)src="([^"]+)"', text):
            url = m.strip()

            # Decode %20, etc.
            url = unquote(url)

            # Strip query/hash
            path = urlparse(url).path

            # If CSS or junk is appended after extension, clip at the extension.
            for ext in extensions:
                if path.lower().endswith(ext):
                    i = path.lower().rfind(ext)
                    if i != -1:
                        path = path[: i + len(ext)]
                    break

            base = os.path.basename(path)

            if any(base.lower().endswith(ext) for ext in extensions):
                refs.add(base)

        return refs

    def get_used_media(tag: str | None = None) -> set[str]:
        """Return a set of media filenames referenced in notes.
        If `tag` is provided, only notes containing that tag are scanned.
        Anki stores tags as a space-padded, normalized string in `notes.tags`.
        We therefore search using a LIKE pattern with spaces on both sides.
        """
        db = mw.col.db
        if tag:
            # Match the exact tag within the space-padded tags string
            like_pat = f"% {tag} %"
            rows = db.all("SELECT flds FROM notes WHERE tags LIKE ?", like_pat)
        else:
            rows = db.all("SELECT flds FROM notes")

        used = set()
        for (flds,) in rows:
            for field in flds.split("\x1f"):
                used |= normalize_refs(field, MEDIA_EXTENSIONS)
        return used

    def get_existing_media():
        return set(os.listdir(mw.col.media.dir()))

    def export_missing_media(tag: str | None = None):
        used = get_used_media(tag)
        existing = get_existing_media()
        missing = used - existing

        output_dir = os.path.expanduser("~/Desktop/Missing Media files")
        os.makedirs(output_dir, exist_ok=True)

        profile_name = mw.pm.name
        output_file = os.path.join(output_dir, f"missing_media_{profile_name}.txt")

        try:
            with open(output_file, "w", encoding="utf-8") as f:
                for name in sorted(missing):
                    f.write(name + "\n")
        except Exception as e:
            print(f"❌ Failed to write missing media file: {e}")

        backup_dir = os.path.expanduser("~/ANki/Missing Media/backup")
        os.makedirs(backup_dir, exist_ok=True)
        backup_file = os.path.join(backup_dir, f"missing_media_{profile_name}.txt")

        try:
            with open(backup_file, "w", encoding="utf-8") as f:
                for name in sorted(missing):
                    f.write(name + "\n")
        except Exception as e:
            print(f"❌ Failed to write backup missing media file: {e}")

        return output_file, len(missing), bool(tag)

    def run_missing_media_check():
        # Determine if we should filter by tag; if TAG_NAME is empty/whitespace, fall back to scanning all notes
        effective_tag = None
        if TAG_FILTER_ENABLED and isinstance(TAG_NAME, str) and TAG_NAME.strip():
            effective_tag = TAG_NAME.strip()
        
        path, count, used_tag_scope = export_missing_media(effective_tag)
        scope_text = f"only notes tagged '{effective_tag}'" if used_tag_scope else "all notes"
        showInfo(
            "✅ Missing media check complete.\n\n"
            f"🔎 Scanned: {scope_text}\n"
            f"📦 {count} missing files saved to:\n{path}"
        )

    run_missing_media_check()

if __name__ == "__main__":
    write_missing_file()  # which defines and runs everything inside