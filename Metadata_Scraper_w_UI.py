#!/usr/bin/env python3

#############################
import os
import sys
import stat
import json
import subprocess
import hashlib
import mimetypes
import plistlib
import getpass
import pwd
import grp
import argparse
from pathlib import Path
from datetime import datetime
#############################


# GUI for picking the file
try:
    import tkinter as tk
    from tkinter import filedialog
except Exception:
    tk = None
    filedialog = None

#' Optional extras:
try:
    from PIL import Image
    from PIL.ExifTags import TAGS as PIL_EXIF_TAGS
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

try:
    import exifread
    EXIFREAD_AVAILABLE = True
except Exception:
    EXIFREAD_AVAILABLE = False

try:
    import PyPDF2
    PYPDF2_AVAILABLE = True
except Exception:
    PYPDF2_AVAILABLE = False


def pick_file_gui():
    if filedialog is None:
        raise RuntimeError("tkinter not available. Run with a path argument instead.")
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    filename = filedialog.askopenfilename(title="Select a file to inspect")
    root.destroy()
    return filename


def run_cmd(cmd):
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return out
    except subprocess.CalledProcessError as e:
        return e.output


def safe_decode(b):
    try:
        return b.decode('utf-8', errors='replace')
    except Exception:
        return str(b)


def get_mdls_metadata(path):
    """
    Use `mdls -plist` to get Spotlight metadata as a plist, parse to dict.
    """
    cmd = ["mdls", "-plist", path]
    try:
        out = subprocess.check_output(cmd)
        data = plistlib.loads(out)
        return data
    except Exception as e:
        #' fallback: try plain mdls and parse text
        try:
            txt = subprocess.check_output(["mdls", path]).decode('utf-8', errors='replace')
            return {"_mdls_text_fallback": txt}
        except Exception as e2:
            return {"mdls_error": str(e), "mdls_error2": str(e2)}


def get_xattrs(path):
    """
    Use `xattr -l` to list extended attributes and try to read them.
    Values may be shown raw/hex; we attempt best-effort decoding.
    """
    res = {}
    try:
        out = subprocess.check_output(["xattr", "-l", path], stderr=subprocess.STDOUT).decode('utf-8', errors='replace')
        #' output format: attrname:\t<value> or attrname:\t0xHEX
        #' We'll also list names with `xattr -p -l attr filename` if needed.
        #' Simplest parse: split lines of "name:\t..." or "name:\t0x..."
        for line in out.splitlines():
            if not line.strip():
                continue
            if ':' in line:
                name, val = line.split(':', 1)
                name = name.strip()
                val = val.strip()
                res[name] = val
        names_out = subprocess.check_output(["xattr", "-l", path]).decode('utf-8', errors='replace')
    except Exception:
        #' fallback to `xattr -p -l` per attribute via `xattr -l` to get names
        res = {}
        try:
            names = subprocess.check_output(["xattr", "-p", path]).decode('utf-8', errors='replace')
            res["_xattr_raw"] = names
        except Exception as e:
            res["_xattr_error"] = str(e)
            return res

    #' To reliably get names, run `xattr -l` and parse names
    try:
        names_raw = subprocess.check_output(["xattr", path]).decode('utf-8', errors='replace')
        names = [n for n in names_raw.split() if n.strip()]
    except Exception:
        names = list(res.keys())

    for name in names:
        if name in res and res.get(name) and not res[name].startswith("0x"):
            #' already have printable value
            continue
        try:
            #' get raw bytes in hex
            hex_out = subprocess.check_output(["xattr", "-p", name, path])
            #' try to decode as utf-8
            try:
                text = hex_out.decode('utf-8', errors='replace')
                res[name] = text
            except Exception:
                #' fallback: hex string
                res[name] = hex_out.hex()
        except Exception as e:
            res[name] = f"<error reading: {e}>"

    return res


def stat_info(path):
    st = os.stat(path)
    info = {
        "size_bytes": st.st_size,
        "mode": stat.filemode(st.st_mode),
        "mode_octal": oct(st.st_mode & 0o7777),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "owner": None,
        "group": None,
        "nlink": st.st_nlink,
        "device": st.st_dev,
        "inode": st.st_ino,
        "atime": datetime.fromtimestamp(st.st_atime).isoformat(),
        "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(),
        "ctime": datetime.fromtimestamp(st.st_ctime).isoformat(),
    }
    try:
        info["owner"] = pwd.getpwuid(st.st_uid).pw_name
    except Exception:
        info["owner"] = st.st_uid
    try:
        info["group"] = grp.getgrgid(st.st_gid).gr_name
    except Exception:
        info["group"] = st.st_gid
    return info


def calc_hashes(path, algorithms=("md5", "sha1", "sha256")):
    results = {}
    hash_objs = {}
    for a in algorithms:
        hash_objs[a] = hashlib.new(a)
    bufsize = 256 * 1024
    try:
        with open(path, "rb") as f:
            while True:
                data = f.read(bufsize)
                if not data:
                    break
                for h in hash_objs.values():
                    h.update(data)
        for a, h in hash_objs.items():
            results[a] = h.hexdigest()
    except Exception as e:
        results["_error"] = str(e)
    return results


def mime_info(path):
    guess, enc = mimetypes.guess_type(path)
    res = {"mimetypes_guess": guess, "encoding_guess": enc}
    try:
        out = subprocess.check_output(["file", "--mime-type", "-b", path]).decode('utf-8', errors='replace').strip()
        res["file_cmd_mime"] = out
    except Exception as e:
        res["file_cmd_mime_error"] = str(e)
    return res


def ls_acl_info(path):
    try:
        out = subprocess.check_output(["ls", "-le", path]).decode('utf-8', errors='replace')
        return out.strip()
    except Exception as e:
        return f"<error: {e}>"


def extract_exif_pillow(path):
    if not PIL_AVAILABLE:
        return {"pillow": "not installed"}
    try:
        im = Image.open(path)
        exif_data = {}
        info = im._getexif()
        if not info:
            return {"pillow_exif": None}
        for tag_id, value in info.items():
            tag = PIL_EXIF_TAGS.get(tag_id, tag_id)
            exif_data[str(tag)] = value
        return exif_data
    except Exception as e:
        return {"pillow_exif_error": str(e)}


def extract_exif_exifread(path):
    if not EXIFREAD_AVAILABLE:
        return {"exifread": "not installed"}
    try:
        with open(path, "rb") as f:
            tags = exifread.process_file(f, details=False)
        # convert tags to simple dict
        return {str(k): str(v) for k, v in tags.items()}
    except Exception as e:
        return {"exifread_error": str(e)}


def extract_pdf_metadata(path):
    if not PYPDF2_AVAILABLE:
        return {"pypdf2": "not installed"}
    try:
        with open(path, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            info = {}
            #' PDF metadata stored in documentInfo / metadata
            try:
                meta = reader.metadata
                if meta:
                    #' metadata keys may be like '/Title etc.'
                    info = {str(k): str(v) for k, v in meta.items()}
            except Exception:
                pass
            #' number of pages
            try:
                info["num_pages"] = len(reader.pages)
            except Exception:
                pass
            return info
    except Exception as e:
        return {"pypdf2_error": str(e)}


def build_metadata(path):
    path = os.fspath(path)
    p = Path(path)
    meta = {
        "path": path,
        "basename": p.name,
        "abspath": str(p.resolve()),
        "is_file": p.is_file(),
        "is_dir": p.is_dir(),
    }

    meta["stat"] = stat_info(path)
    meta["hashes"] = calc_hashes(path)
    meta["mime"] = mime_info(path)
    meta["ls_acl"] = ls_acl_info(path)
    meta["mdls"] = get_mdls_metadata(path)
    meta["xattr"] = get_xattrs(path)

    #' Spot-check MIME type to decide on EXIF/PDF
    file_mime = meta["mime"].get("file_cmd_mime") or meta["mime"].get("mimetypes_guess", "")
    if file_mime.startswith("image/") or p.suffix.lower() in (".jpg", ".jpeg", ".tiff", ".cr2", ".nef", ".raw", ".png"):
        exif = {}
        if PIL_AVAILABLE:
            exif["pillow"] = extract_exif_pillow(path)
        if EXIFREAD_AVAILABLE:
            exif["exifread"] = extract_exif_exifread(path)
        meta["exif"] = exif

    if p.suffix.lower() == ".pdf" or (file_mime == "application/pdf"):
        meta["pdf"] = extract_pdf_metadata(path)

    #' Try to include owner info if possible
    try:
        stat_info_dict = meta.get("stat", {})
        uid = stat_info_dict.get("uid", None)
        if uid is None:
            uid = os.stat(path).st_uid
        meta["owner_username"] = pwd.getpwuid(uid).pw_name
    except Exception:
        pass

    try:
        with open(path, "rb") as f:
            sample = f.read(1024)
            meta["sample_first_1kb_hex"] = sample.hex()
            try:
                sample.decode('utf-8')
                meta["sample_is_text_utf8"] = True
            except Exception:
                meta["sample_is_text_utf8"] = False
    except Exception as e:
        meta["sample_error"] = str(e)

    return meta


def main():
    parser = argparse.ArgumentParser(description="Gather metadata for a file on macOS.")
    parser.add_argument("path", nargs="?", help="Path to file. If omitted, a GUI file picker will open (tkinter).")
    parser.add_argument("--save", action="store_true", help="Save metadata to metadata_<basename>.json")
    parser.add_argument("--no-sample", action="store_true", help="Don't include first-1KB sample hex.")
    args = parser.parse_args()

    if args.path:
        path = args.path
    else:
        try:
            path = pick_file_gui()
        except Exception as e:
            print("Failed to open GUI file picker (tkinter). Provide path as argument. Error:", e, file=sys.stderr)
            sys.exit(1)

    if not path:
        print("No file selected. Exiting.", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(path):
        print(f"Path does not exist: {path}", file=sys.stderr)
        sys.exit(1)

    meta = build_metadata(path)
    if args.no_sample:
        meta.pop("sample_first_1kb_hex", None)
        meta.pop("sample_is_text_utf8", None)

    json_out = json.dumps(meta, indent=2, ensure_ascii=False)
    print(json_out)

    if args.save:
        base = Path(path).name
        safe_base = base.replace(" ", "_")
        out_name = f"metadata_{safe_base}.json"
        with open(out_name, "w", encoding="utf-8") as f:
            f.write(json_out)
        print(f"\nSaved metadata to {out_name}")


if __name__ == "__main__":
    main()
