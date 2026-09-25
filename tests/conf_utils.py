"""Helpers for reading Splunk .conf files in tests."""

import re
from configparser import RawConfigParser
from io import StringIO
from pathlib import Path


def load_conf(path):
    """Parse a Splunk conf file, joining backslash-continued lines first."""
    raw = Path(path).read_text(encoding="utf-8")
    joined = re.sub(r"\\\s*\n\s*", " ", raw)
    parser = RawConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    parser.read_file(StringIO(joined), source=str(path))
    return parser


def stanza(parser, name):
    return {key: parser.get(name, key) for key in parser.options(name)}


def table_fields(search):
    """Return field names from the last `| table ...` command in an SPL string."""
    matches = re.findall(r"\|\s*table\s+([^|]+)", search)
    assert matches, "expected a table command in: {}".format(search)
    return {field.strip() for field in matches[-1].split(",") if field.strip()}
