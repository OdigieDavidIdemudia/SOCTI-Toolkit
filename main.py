#!/usr/bin/env python3
import sys
import argparse


def add_separator(s: str, sep: str = ',') -> str:
    """Return tokens from input string joined by sep.

    - Treat existing commas as token separators as well.
    - Collapse any whitespace and skip empty tokens.
    - Handles any input including special characters.
    """
    if s is None:
        return ""
    # Normalize commas to spaces so both spaces and commas split tokens.
    normalized = s.replace(',', ' ')
    tokens = [t for t in normalized.split() if t]
    return sep.join(tokens)


def main():
    parser = argparse.ArgumentParser(description='Insert a separator between tokens in a string.')
    parser.add_argument('input', nargs='?', help='Input string. If omitted, reads from stdin.')
    parser.add_argument('-s', '--sep', default=',', help='Separator to use (default: ",").')
    args = parser.parse_args()

    if args.input:
        inp = args.input
    else:
        # Read entire stdin (useful for piping)
        inp = sys.stdin.read().strip()

    result = add_separator(inp, args.sep)
    print(result)


if __name__ == '__main__':
    main()
