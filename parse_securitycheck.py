import sys
import re


def read_file(filename):
    """Read a log, trying the encodings SecurityCheck is known to write."""
    for encoding in ('utf-16', 'utf-8-sig', 'utf-8', 'latin-1'):
        try:
            with open(filename, encoding=encoding) as f:
                return f.read()
        except (UnicodeDecodeError, UnicodeError):
            continue
    raise ValueError(f"Could not decode '{filename}'")


# SecurityCheck exists in several locales/versions, so every marker has variants:
# "Warning!" (current EN), "Attention!" (older EN builds), "Внимание!" (RU).
WARN = r'(?:Warning!|Attention!|Внимание!)'
DOWNLOAD_LABEL = r'(?:Download\s+Updates?|Скачать\s+обновления)'
EOL = r'(?:no longer supported|больше не поддерживается)'
REMOTE = r'(?:Remote desktop software!|Remote access program!|Программа для удал[её]нного)'
SETTING_LABEL = r'(User Account Control|The elevation prompt for .+?)'
UAC_LINE = r'^' + SETTING_LABEL + r'\s*\[color=red\]\[b\](.+?)\[/b\]'
RECOMMEND = r'(?:It is recommended to uninstall|Uninstallation recommended|Рекомендуется удалить|Рекомендуется деинсталляция)'


def _strip_bb(text):
    text = re.sub(r'\[i\].*?\[/i\]', '', text)
    text = re.sub(r'\[/?[^\]]*\]', '', text)
    return re.sub(r'\s+', ' ', text.replace('^', '')).strip(' .')


def _app_name(line):
    """Everything before the first bbcode tag is the program name."""
    return re.split(r'\s*\[(?:b|color|i|url)[^\]]*\]', line, maxsplit=1)[0].strip()


def _warning_segments(line):
    """Split a line into one chunk per warning marker (a line can carry several).

    Returns (offset, text) pairs; the offset is the chunk's position in the line,
    so a link belonging to a chunk can be looked up without rescanning the rest.
    """
    marks = list(re.finditer(WARN, line))
    segments = []
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(line)
        segments.append((m.end(), line[m.end():end]))
    return segments


def parse_lines(content):
    results = []
    windows_version = None
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue

        win_match = re.match(r'(Windows \d+ \S+ \(\w+\)) Release: (\w+)', line)
        if win_match:
            windows_version = f"{win_match.group(1)} {win_match.group(2)}"
            continue

        uac_match = re.match(UAC_LINE, line)
        if uac_match:
            results.append({'type': 'setting', 'setting': uac_match.group(1).strip(),
                            'state': _strip_bb(uac_match.group(2))})
            continue

        # Standalone red system setting, e.g. "Never check for updates" or a
        # fully wrapped "[color=red][b]User Account Control [b]disabled[/b][/b][/color]".
        if line.startswith('[color=red]') and not _app_name(line):
            text = _strip_bb(line)
            if text:
                labelled = re.match(SETTING_LABEL + r'\s+(.+)$', text)
                if labelled:
                    results.append({'type': 'setting', 'setting': labelled.group(1),
                                    'state': labelled.group(2)})
                else:
                    results.append({'type': 'setting', 'setting': text, 'state': ''})
            continue

        # Standalone advice line printed underneath the program it belongs to.
        if line.startswith('[color=blue]'):
            url_match = re.search(r'\[url=(.*?)\]([^\[]+)\[/url\]', line)
            if url_match and 'update errors' in _strip_bb(line).lower():
                results.append({'type': 'note', 'subject': url_match.group(2).strip(),
                                'url': url_match.group(1)})
            else:
                hint = _strip_bb(line)
                if hint and results:
                    previous = results[-1].get('hint')
                    results[-1]['hint'] = f"{previous}; {hint}" if previous else hint
            continue

        has_warning = bool(re.search(WARN, line))
        if not has_warning and not re.search(RECOMMEND, line, re.I):
            continue

        app = _app_name(line)
        if not app:
            continue

        if not has_warning:
            reason = _strip_bb(line[len(app):])
            if reason:
                results.append({'type': 'unwanted', 'app': app, 'reason': reason})
            continue
        if app == 'Extended support has ended' and windows_version:
            app = f"{windows_version} - Extended support has ended"

        handled = False
        segments = _warning_segments(line)
        # Only a notice that belongs to a warning counts; the same words inside
        # a PUP description must not turn the entry into an end-of-life one.
        eol_at = next((offset + m.start() for offset, text in segments
                       for m in [re.search(EOL, text, re.I)] if m), None)

        # A dead product is not worth updating, so end-of-life wins over the
        # update link such a line often carries as well.
        if eol_at is None:
            for url in re.findall(r'\[url=(.*?)\]\s*' + DOWNLOAD_LABEL + r'\s*\[/url\]', line, re.I):
                results.append({'type': 'update', 'app': app, 'url': url})
                handled = True
        else:
            # The replacement link follows the notice; older builds print none.
            url_match = re.search(r'\[url=(.*?)\]', line[eol_at:])
            results.append({'type': 'eol', 'app': app,
                            'url': url_match.group(1) if url_match else None})
            handled = True

        if re.search(REMOTE, line, re.I):
            results.append({'type': 'remote_desktop', 'app': app})
            handled = True

        for _, segment in segments:
            reason = _strip_bb(segment)
            if not reason:
                continue
            if re.fullmatch(DOWNLOAD_LABEL, reason, re.I):
                continue
            if re.search(EOL, reason, re.I) or re.search(REMOTE, reason, re.I):
                continue
            results.append({'type': 'unwanted', 'app': app, 'reason': reason})
            handled = True

        if not handled:
            results.append({'type': 'unwanted', 'app': app, 'reason': ''})

    return results


def _hint(r):
    return f" ({r['hint']})" if r.get('hint') else ""


# Section headings, in output order. Outdated / end-of-life software belongs
# with the programs to uninstall, not with the ones that can simply be updated.
SECTIONS = (
    (('update',), "Please update the following software:"),
    (('unwanted', 'eol'), "Please remove the following potentially unwanted programs (PUP):"),
    (('remote_desktop',), "Please let me know whether you recognize this remote desktop software (if not, uninstall it):"),
    (('setting',), "Please check the following Windows settings:"),
)


def _format(results, markdown):
    """Render the parsed results as plain text, or as Reddit-flavoured markdown."""
    def bold(text):
        return f"**{text}**" if markdown else text

    def bullet(text):
        return f"* {text}" if markdown else text

    def link(url, label):
        return f"[{label}]({url})" if markdown else f"{label} {url}"

    def entry(r):
        if r['type'] == 'update':
            label = "New update available, download here" if markdown else "Download Update"
            return f"{bold(r['app'])} | {link(r['url'], label)}"
        if r['type'] == 'eol':
            reason = "No longer supported - please uninstall it"
            if r.get('url'):
                replacement = link(r['url'], "replace it here" if markdown else "replace it with")
                reason = f"{reason} and {replacement}"
            return f"{bold(r['app'])} - {reason}"
        if r['type'] == 'setting':
            state = f" - {r['state']}" if r['state'] else ""
            return f"{bold(r['setting'])}{state}"
        reason = r.get('reason', '')
        return f"{bold(r['app'])} - {reason}" if reason else bold(r['app'])

    lines = []
    for types, heading in SECTIONS:
        section = [r for r in results if r['type'] in types]
        if not section:
            continue
        lines.append(bold(heading))
        lines.extend(bullet(entry(r)) + _hint(r) for r in section)
        lines.append("")

    for r in results:
        if r['type'] == 'note':
            note = f"Note: If {r['subject']} update errors occur, " + link(
                r['url'], "reinstall here" if markdown else "reinstall from")
            lines.append(f"*{note}*" if markdown else note)

    return lines


def format_malwarebytes(results):
    return _format(results, markdown=False)


def format_reddit(results):
    return _format(results, markdown=True)


def read_clipboard():
    import tkinter as tk
    root = tk.Tk()
    root.withdraw()
    try:
        return root.clipboard_get()
    finally:
        root.destroy()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python parse_securitycheck.py <malwarebytes|reddit> [SecurityCheck.txt]")
        print("       If no file is given, clipboard content is used (must start with 'SecurityCheck by ').")
        sys.exit(1)

    mode = sys.argv[1].lower()

    if mode not in ('malwarebytes', 'reddit'):
        print(f"Error: Unknown mode '{mode}'. Use 'malwarebytes' or 'reddit'.", file=sys.stderr)
        sys.exit(1)

    if len(sys.argv) >= 3:
        filename = sys.argv[2]
        try:
            content = read_file(filename)
        except FileNotFoundError:
            print(f"Error: File '{filename}' not found.", file=sys.stderr)
            sys.exit(1)
        except (OSError, ValueError) as e:
            print(f"Error: Could not read '{filename}': {e}", file=sys.stderr)
            sys.exit(1)
    else:
        try:
            content = read_clipboard()
        except Exception as e:
            print(f"Error: Could not read clipboard: {e}", file=sys.stderr)
            sys.exit(1)
        if not content.startswith("SecurityCheck by "):
            print("Error: Clipboard content does not start with 'SecurityCheck by '.", file=sys.stderr)
            sys.exit(1)

    results = parse_lines(content)
    output = format_malwarebytes(results) if mode == 'malwarebytes' else format_reddit(results)

    if output:
        for line in output:
            print(line)
    else:
        print("No items found.")
