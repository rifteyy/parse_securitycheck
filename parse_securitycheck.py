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


def parse_lines(content):
    results = []
    for line in content.splitlines():
        line = line.strip()

        if '[color=red]' in line and 'Warning!' in line and 'Download Update' in line:
            app_part = re.sub(r'\s*\[color=red\].*$', '', line).strip()
            url_match = re.search(r'\[url=(.*?)\]Download Update\[/url\]', line)
            if url_match:
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

    return results


def format_malwarebytes(results):
    lines = []
    for r in results:
        if r['type'] == 'update':
            lines.append(f"{r['app']} | Download Update {r['url']}")
        elif r['type'] == 'eol':
            lines.append(f"{r['app']} | No longer supported - Replace with {r['url']}")
        elif r['type'] == 'note':
            lines.append(f"Note: If {r['subject']} update errors occur, reinstall from {r['url']}")
    return lines


def format_reddit(results):
    lines = []
    for r in results:
        if r['type'] == 'update':
            lines.append(f"**{r['app']}** | New update available, [download here]({r['url']})")
        elif r['type'] == 'eol':
            lines.append(f"**{r['app']}** | No longer supported, [replace here]({r['url']})")
        elif r['type'] == 'note':
            lines.append(f"*Note: If {r['subject']} update errors occur, [reinstall here]({r['url']})*")
        lines.append("")
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
        print("No outdated applications found.")
