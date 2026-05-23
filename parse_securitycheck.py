import sys
import re


def read_file(filename):
    content = None
    for encoding in ('utf-16', 'utf-8-sig', 'utf-8', 'latin-1'):
        try:
            with open(filename, encoding=encoding) as f:
                content = f.read()
            break
        except (UnicodeDecodeError, UnicodeError):
            continue
    if content is None:
        print(f"Error: Could not read '{filename}'", file=sys.stderr)
        sys.exit(1)
    return content


def _extract_plain_reason(line):
    after = re.sub(r'.*\[b\]Warning!\[/b\]\s*', '', line)
    after = re.sub(r'\[/?[^\]]+\]', '', after)
    return after.strip()


def parse_lines(content):
    results = []
    windows_version = None
    for line in content.splitlines():
        line = line.strip()

        win_match = re.match(r'(Windows \d+ \S+ \(\w+\)) Release: (\w+)', line)
        if win_match:
            windows_version = f"{win_match.group(1)} {win_match.group(2)}"

        if '[color=red]' in line and 'Warning!' in line and 'Download Update' in line:
            app_part = re.sub(r'\s*\[color=red\].*$', '', line).strip()
            url_match = re.search(r'\[url=(.*?)\]Download Update\[/url\]', line)
            if url_match:
                if app_part == 'Extended support has ended' and windows_version:
                    app_part = f"{windows_version} - Extended support has ended"
                results.append({'type': 'update', 'app': app_part, 'url': url_match.group(1)})

        elif '[color=red]' in line and 'no longer supported' in line.lower():
            app_part = re.sub(r'\s*\[b\]\[color=red\].*$', '', line).strip()
            url_match = re.search(r'\[url=(.*?)\]', line)
            if url_match:
                results.append({'type': 'eol', 'app': app_part, 'url': url_match.group(1)})

        elif '[color=blue]' in line and '[url=' in line:
            url_match = re.search(r'\[url=(.*?)\]([^\[]+)\[/url\]', line)
            if url_match:
                results.append({'type': 'note', 'subject': url_match.group(2).strip(), 'url': url_match.group(1)})

        elif 'Remote desktop software!' in line:
            app_part = re.sub(r'\s*\[b\]\[color=red\].*$', '', line).strip()
            if app_part:
                results.append({'type': 'remote_desktop', 'app': app_part})

        elif '[color=red]' in line and 'Warning!' in line:
            app_part = re.sub(r'\s*\[b\]\[color=red\].*$', '', line).strip()
            reason_match = re.search(r'\[color=red\]Warning!\s*(.*?)\[/color\]', line)
            reason = reason_match.group(1).strip() if reason_match else ''
            if app_part:
                results.append({'type': 'unwanted', 'app': app_part, 'reason': reason})

        elif '[b]Warning![/b]' in line:
            app_part = re.sub(r'\s*\[b\]Warning!\[/b\].*$', '', line).strip()
            if app_part:
                results.append({'type': 'unwanted', 'app': app_part, 'reason': _extract_plain_reason(line)})

    return results


def format_malwarebytes(results):
    lines = []

    updates = [r for r in results if r['type'] in ('update', 'eol')]
    unwanted = [r for r in results if r['type'] == 'unwanted']
    remote_desktops = [r for r in results if r['type'] == 'remote_desktop']
    notes = [r for r in results if r['type'] == 'note']

    if updates:
        lines.append("Please update the following software:")
        for r in updates:
            if r['type'] == 'update':
                lines.append(f"{r['app']} | Download Update {r['url']}")
            elif r['type'] == 'eol':
                lines.append(f"{r['app']} | No longer supported - Replace with {r['url']}")
        lines.append("")

    if unwanted:
        lines.append("Please remove the following potentially unwanted programs (PUP):")
        for r in unwanted:
            reason = r.get('reason', '')
            lines.append(f"{r['app']} - {reason}" if reason else r['app'])
        lines.append("")

    if remote_desktops:
        lines.append("Please let me know whether you recognize this remote desktop software:")
        for r in remote_desktops:
            lines.append(r['app'])
        lines.append("")

    for r in notes:
        lines.append(f"Note: If {r['subject']} update errors occur, reinstall from {r['url']}")

    return lines


def format_reddit(results):
    lines = []

    updates = [r for r in results if r['type'] in ('update', 'eol')]
    unwanted = [r for r in results if r['type'] == 'unwanted']
    remote_desktops = [r for r in results if r['type'] == 'remote_desktop']
    notes = [r for r in results if r['type'] == 'note']

    if updates:
        lines.append("**Please update the following software:**")
        for r in updates:
            if r['type'] == 'update':
                lines.append(f"* **{r['app']}** | [New update available, download here]({r['url']})")
            elif r['type'] == 'eol':
                lines.append(f"* **{r['app']}** | [No longer supported, replace here]({r['url']})")
        lines.append("")

    if unwanted:
        lines.append("**Please remove the following potentially unwanted programs (PUP):**")
        for r in unwanted:
            reason = r.get('reason', '')
            lines.append(f"* **{r['app']}** - {reason}" if reason else f"* **{r['app']}**")
        lines.append("")

    if remote_desktops:
        lines.append("**Please let me know whether you recognize this remote desktop software:**")
        for r in remote_desktops:
            lines.append(f"* **{r['app']}**")
        lines.append("")

    for r in notes:
        lines.append(f"*Note: If {r['subject']} update errors occur, [reinstall here]({r['url']})*")

    return lines


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python parse_securitycheck.py <malwarebytes|reddit> <SecurityCheck.txt>")
        sys.exit(1)

    mode = sys.argv[1].lower()
    filename = sys.argv[2]

    if mode not in ('malwarebytes', 'reddit'):
        print(f"Error: Unknown mode '{mode}'. Use 'malwarebytes' or 'reddit'.", file=sys.stderr)
        sys.exit(1)

    try:
        content = read_file(filename)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.", file=sys.stderr)
        sys.exit(1)

    results = parse_lines(content)
    output = format_malwarebytes(results) if mode == 'malwarebytes' else format_reddit(results)

    if output:
        for line in output:
            print(line)
    else:
        print("No items found.")
