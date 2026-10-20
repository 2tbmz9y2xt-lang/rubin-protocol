"""Every literal flag on the Go rubin-node FlagSet needs a classification row: an
existing native negative startup-validation anchor or the boolean-switch reason."""

from __future__ import annotations

import copy
import itertools
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAIN_GO = "clients/go/cmd/rubin-node/main.go"
START = 'fs := flag.NewFlagSet("rubin-node", '
PARSE = "fs.Parse(args)"
REASON = "PARSER_ONLY_BOOLEAN_SWITCH"
LABELS = frozenset(
    "SENTINEL UNSUPPORTED_SHAPE DYNAMIC_NAME DUPLICATE_FLAG MISSING_ROW STALE_ROW "
    "ROW_SHAPE ANCHOR_PATH ANCHOR_SYMBOL REASON_INVALID CLASSIFICATION_MISMATCH".split()
)
FIRST_ARG = "Bool String Int Uint Uint64 Duration Float64 Func".split()
SECOND_ARG = "BoolVar StringVar IntVar UintVar Uint64Var DurationVar Float64Var Var TextVar".split()
NAME_ARG = {**{m: 0 for m in FIRST_ARG}, **{m: 1 for m in SECOND_ARG}}
BOOL_METHODS = frozenset(("Bool", "BoolVar"))

CFG = "clients/go/node/config_test.go"
MAIN_TEST = "clients/go/cmd/rubin-node/main_test.go"
TYPED = "TestRunRejectsInvalidTypedFlagValuesAtFlagParse"


def _anchor(path: str, symbol: str) -> dict:
    return {"anchor": {"path": path, "symbol": symbol}}


EXPECTED = {
    "--peers": _anchor(CFG, "TestValidateConfigRejectsBadPeer"),
    "--peer": _anchor(CFG, "TestValidateConfigRejectsBadPeer"),
    "--network": _anchor(CFG, "TestValidateConfigRejectsEmptyNetwork"),
    "--datadir": _anchor(CFG, "TestValidateConfigRejectsEmptyDataDir"),
    "--bind": _anchor(CFG, "TestValidateConfigRejectsBadBind"),
    "--rpc-bind": _anchor(CFG, "TestValidateConfigRejectsBadRPCBindAddr"),
    "--log-level": _anchor(CFG, "TestValidateConfigRejectsInvalidLogLevel"),
    "--genesis-file": _anchor(MAIN_TEST, "TestRunRejectsInvalidGenesisFileBeforeDataDirCreate"),
    "--max-peers": _anchor(MAIN_TEST, "TestRunInvalidConfigMaxPeers"),
    "--mempool-max-txs": _anchor(MAIN_TEST, "TestRunInvalidConfigMempoolLimits"),
    "--mempool-max-bytes": _anchor(MAIN_TEST, "TestRunInvalidConfigMempoolLimits"),
    "--da-mempool-size": _anchor(MAIN_TEST, "TestRunDAMempoolSizeFlag"),
    "--mine-address": _anchor(MAIN_TEST, "TestRunRejectsInvalidMineAddressBeforeStorage"),
    "--mine-blocks": _anchor(MAIN_TEST, TYPED),
    "--featurebits-deployments": _anchor(MAIN_TEST, "TestRunRejectsInvalidFeatureBitsDeploymentsBeforeStorage"),
    "--pv-mode": _anchor(MAIN_TEST, "TestRunRejectsInvalidPVModeBeforeStorage"),
    "--pv-shadow-max": _anchor(MAIN_TEST, TYPED),
    "--legacy-suite-id": _anchor(MAIN_TEST, "TestRunLegacyExposureScanRejectsInvalidSuiteID"),
    **{
        flag: {"reason": REASON}
        for flag in "--mine-exit --legacy-exposure-scan --legacy-exposure-include-outpoints "
        "--dry-run --create-store".split()
    },
}

TOKEN_RE = re.compile(
    r"""(?P<COMMENT>//[^\n]*|/\*.*?\*/)
    |(?P<STR>"(?:\\.|[^"\\\n])*")
    |(?P<RAW>`[^`]*`)
    |(?P<RUNE>'(?:\\.|[^'\\\n])+')
    |(?P<BAD>["'`]|/\*)
    |(?P<WS>\s+)
    |(?P<IDENT>\w+)
    |(?P<PUNCT>.)""",
    re.DOTALL | re.VERBOSE,
)


def tokenize(text: str) -> list[tuple[str, str, int, int]]:
    """Tokens (kind, text, line, column) without comments and blanks; an unterminated
    literal or comment ends the list as a BAD token."""
    tokens, line, line_start = [], 1, 0
    for m in TOKEN_RE.finditer(text):
        kind, value = m.lastgroup, m.group()
        if kind not in ("COMMENT", "WS"):
            tokens.append((kind, value, line, m.start() - line_start))
        if kind == "BAD":
            break
        if "\n" in value:
            line += value.count("\n")
            line_start = m.start() + value.rindex("\n") + 1
    return tokens


def split_args(tokens: list, open_idx: int) -> list[list] | None:
    """Top-level arguments of the call whose '(' is tokens[open_idx]; None if unbalanced."""
    args, cur, depth = [], [], 0
    for tok in tokens[open_idx:]:
        text = tok[1] if tok[0] == "PUNCT" else ""
        depth += text in ("(", "[", "{")
        depth -= text in (")", "]", "}")
        if depth == 0:
            return args + [cur] if cur else args
        if depth == 1 and text == ",":
            args.append(cur)
            cur = []
        elif not (depth == 1 and text == "(" and tok is tokens[open_idx]):
            cur.append(tok)
    return None


def sentinel_loc(hits: list[int]) -> str:
    return f"{MAIN_GO}:{hits[-1] + 1}" if hits else MAIN_GO


def sentinel_failures(lines: list[str]) -> tuple[list, int, int]:
    starts = [i for i, ln in enumerate(lines) if START in ln]
    parses = [i for i, ln in enumerate(lines) if PARSE in ln]
    fails = [("SENTINEL", sentinel_loc(hits)) for hits in (starts, parses) if len(hits) != 1]
    if not fails and parses[0] <= starts[0]:
        fails.append(("SENTINEL", sentinel_loc(parses)))
    return (fails, 0, 0) if fails else (fails, starts[0], parses[0])


GO_ESCAPE = re.compile(
    r'\\(?:(?P<c>[abfnrtv\\"])|x(?P<x>[0-9a-fA-F]{2})|u(?P<u>[0-9a-fA-F]{4})'
    r"|U(?P<U>[0-9a-fA-F]{8})|(?P<o>[0-7]{3}))|(?P<t>[^\\]+)|(?P<bad>.)",
    re.DOTALL,
)
SIMPLE_ESCAPES = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11, "\\": 92, '"': 34}


def escape_bytes(kind: str, text: str) -> bytes:
    if kind == "t":
        return text.encode()
    if kind == "c":
        return bytes([SIMPLE_ESCAPES[text]])
    if kind in ("x", "o"):
        return bytes([int(text, 16 if kind == "x" else 8)])
    return chr(int(text, 16)).encode()


def literal_name(literal: str) -> str | None:
    """Go name of a double-quoted literal; None when it is not exactly representable."""
    out = bytearray()
    try:
        for m in GO_ESCAPE.finditer(literal[1:-1]):
            if m.lastgroup == "bad":
                return None
            out += escape_bytes(m.lastgroup, m.group(m.lastgroup))
        return out.decode("utf-8")
    except (ValueError, OverflowError):
        return None


def registration(tokens: list, i: int) -> tuple[str | None, str | None, tuple | None]:
    loc = f"{MAIN_GO}:{tokens[i][2]}"
    shape = (None, None, ("UNSUPPORTED_SHAPE", loc))
    if i + 3 >= len(tokens) or tokens[i + 1][1] != "." or (i and tokens[i - 1][1] == "."):
        return shape
    if tokens[i + 3][1] != "(":
        return shape
    method = tokens[i + 2][1]
    if method == "SetOutput":
        return None, None, None
    if method not in NAME_ARG:
        return shape
    args = split_args(tokens, i + 3)
    if args is None or len(args) <= NAME_ARG[method]:
        return shape
    arg = args[NAME_ARG[method]]
    if len(arg) != 1 or arg[0][0] != "STR":
        return None, None, ("DYNAMIC_NAME", loc)
    name = literal_name(arg[0][1])
    return shape if name is None else (name, method, None)


def is_fs(tok: tuple) -> bool:
    return tok[:2] == ("IDENT", "fs")


def sentinel_is_code(bare_fs: set, line_no: int, line: str, text: str) -> bool:
    """Every occurrence of the sentinel text on the line begins with a code `fs` token
    that does not follow a `.` token."""
    return all((line_no, m.start()) in bare_fs for m in re.finditer(re.escape(text), line))


def sentinel_line_failures(tokens: list, lines: list[str], start: int, end: int) -> list:
    """Every code `fs` on a sentinel line other than the sentinel's own, and every
    sentinel line whose sentinel text is not code or follows a `.` token."""
    texts = {start + 1: START, end + 1: PARSE}
    own = {n: lines[n - 1].index(text) for n, text in texts.items()}
    code_fs = [t[2:] for t in tokens if is_fs(t)]
    bare_fs = {t[2:] for i, t in enumerate(tokens) if is_fs(t) and not (i and tokens[i - 1][1] == ".")}
    bad = [n for n, col in code_fs if n in own and col != own[n]]
    bad += [n for n, text in texts.items() if not sentinel_is_code(bare_fs, n, lines[n - 1], text)]
    return [("UNSUPPORTED_SHAPE", f"{MAIN_GO}:{n}") for n in bad]


def registration_call(tokens: list, i: int) -> bool:
    """tokens[i:i + 4] are `fs`, `.`, a supported registration method and `(`."""
    window = tokens[i : i + 4]
    return (
        len(window) == 4
        and is_fs(window[0])
        and window[1][1] == "."
        and window[2][1] in NAME_ARG
        and window[3][1] == "("
    )


def outside_failures(tokens: list, start: int, end: int) -> list:
    """Registration calls on `fs` before the start line or after the end line, and an
    unterminated literal or comment after the end line (scanning stops there)."""
    fails = []
    for i, tok in enumerate(tokens):
        before, after = tok[2] <= start, tok[2] > end + 1
        if (after and tok[0] == "BAD") or ((before or after) and registration_call(tokens, i)):
            fails.append(("UNSUPPORTED_SHAPE", f"{MAIN_GO}:{tok[2]}"))
    return fails


def extract_inventory(source: str) -> tuple[dict[str, str], list[tuple[str, str]]]:
    lines = source.split("\n")
    fails, start, end = sentinel_failures(lines)
    if fails:
        return {}, fails
    tokens = tokenize(source)
    outside = outside_failures(tokens, start, end)
    bad = [t[2] for t in tokens if t[0] == "BAD" and t[2] <= end + 1]
    if bad:
        return {}, [("UNSUPPORTED_SHAPE", f"{MAIN_GO}:{bad[0]}")] + outside
    fails += sentinel_line_failures(tokens, lines, start, end)
    window = [t for t in tokens if t[2] <= end]
    inventory: dict[str, str] = {}
    for i, tok in enumerate(window):
        if tok[2] <= start + 1 or not is_fs(tok):
            continue
        name, method, fail = registration(window, i)
        if fail:
            fails.append(fail)
        elif name is not None and name in inventory:
            fails.append(("DUPLICATE_FLAG", "--" + name))
        elif name is not None:
            inventory[name] = method
    return inventory, fails + outside


def anchor_failures(root: Path, flag: str, anchor: dict) -> list:
    path = (root / anchor["path"]).resolve()
    go_root = (root / "clients/go").resolve()
    ok = anchor["path"].startswith("clients/go/") and anchor["path"].endswith("_test.go")
    if not (ok and path.is_relative_to(go_root) and path.is_file()):
        return [("ANCHOR_PATH", flag)]
    wanted = f"func {anchor['symbol']}(t *testing.T) {{"
    count = path.read_text(encoding="utf-8").split("\n").count(wanted)
    return [] if count == 1 else [("ANCHOR_SYMBOL", flag)]


def row_shape_ok(row: object) -> bool:
    if not isinstance(row, dict) or len(row) != 1:
        return False
    anchor = row.get("anchor")
    if "reason" in row:
        return True
    return (
        isinstance(anchor, dict)
        and set(anchor) == {"path", "symbol"}
        and all(isinstance(v, str) and v for v in anchor.values())
    )


def row_failures(root: Path, flag: str, row: object, method: str | None) -> list:
    if not row_shape_ok(row):
        return [("ROW_SHAPE", flag)]
    if "anchor" in row:
        return anchor_failures(root, flag, row["anchor"])
    if row["reason"] != REASON or (method is not None and method not in BOOL_METHODS):
        return [("REASON_INVALID", flag)]
    return []


def mismatch_failures(classification: dict) -> list:
    keys = EXPECTED.keys() | classification.keys()
    return [
        ("CLASSIFICATION_MISMATCH", flag)
        for flag in sorted(keys)
        if EXPECTED.get(flag) != classification.get(flag)
    ]


def check(root: Path, source: str, classification: dict) -> list[tuple[str, str]]:
    inventory, fails = extract_inventory(source)
    if any(label == "SENTINEL" for label, _ in fails):
        return fails
    flags = {"--" + name: method for name, method in inventory.items()}
    fails += [("MISSING_ROW", f) for f in flags if f not in classification]
    fails += [("STALE_ROW", f) for f in classification if f not in flags]
    for flag, row in classification.items():
        fails += row_failures(root, flag, row, flags.get(flag))
    return fails + mismatch_failures(classification)


def read_main() -> str:
    return (ROOT / MAIN_GO).read_text(encoding="utf-8")


def program(*body: str) -> str:
    return "\n".join(
        ["func run() {", "\t" + START + "flag.ContinueOnError)", *body, "\tif err := " + PARSE + "; err != nil {"]
    )


class LiveInventoryTests(unittest.TestCase):
    def test_a1_inventory_and_methods(self) -> None:
        inventory, fails = extract_inventory(read_main())
        self.assertEqual(fails, [])
        want = dict(
            kv.split("=")
            for kv in (
                "peers=String peer=Var network=StringVar datadir=StringVar bind=StringVar "
                "rpc-bind=StringVar log-level=StringVar genesis-file=String max-peers=IntVar "
                "mempool-max-txs=IntVar mempool-max-bytes=IntVar da-mempool-size=Uint64Var "
                "mine-address=StringVar mine-blocks=Int mine-exit=Bool "
                "featurebits-deployments=String pv-mode=String pv-shadow-max=Uint64 "
                "legacy-exposure-scan=Bool legacy-suite-id=Var "
                "legacy-exposure-include-outpoints=Bool dry-run=Bool create-store=Bool"
            ).split()
        )
        self.assertEqual(inventory, want)
        self.assertEqual(len(EXPECTED), 23)
        self.assertEqual(sum("anchor" in r for r in EXPECTED.values()), 18)

    def test_a2_a3_live_check_passes(self) -> None:
        self.assertEqual(check(ROOT, read_main(), EXPECTED), [])
        rows = [r["anchor"] for r in EXPECTED.values() if "anchor" in r]
        typed = [r for r in rows if r["symbol"] == TYPED]
        self.assertEqual(len(typed), 2)
        self.assertEqual(len(rows) - len(typed), 16)
        self.assertEqual(len({r["symbol"] for r in rows if r["symbol"] != TYPED}), 14)
        self.assertEqual(sum("reason" in r for r in EXPECTED.values()), 5)


class ExtractorCorpusTests(unittest.TestCase):
    def test_a4_every_method_extracted_with_method(self) -> None:
        first = "Bool String Int Uint Uint64 Duration Float64 Func".split()
        second = "BoolVar StringVar IntVar UintVar Uint64Var DurationVar Float64Var Var TextVar".split()
        calls = {m: f'fs.{m}("n", x, "h")' for m in first}
        calls |= {m: f'fs.{m}(&x, "n", x, "h")' for m in second}
        self.assertEqual(len(calls), 17)
        self.assertEqual(set(calls), set(NAME_ARG))
        for method, call in calls.items():
            with self.subTest(method=method):
                self.assertEqual(extract_inventory(program(call)), ({"n": method}, []))

    def test_a4_set_output_and_multiline(self) -> None:
        self.assertEqual(extract_inventory(program("fs.SetOutput(stderr)")), ({}, []))
        split = 'fs.StringVar(\n\t&x,\n\t"split",\n\t"d", "h",\n)'
        self.assertEqual(extract_inventory(program(split)), ({"split": "StringVar"}, []))
        self.assertEqual(extract_inventory(program('fs.Bool("a\\x62c\\u0064", x)')), ({"abcd": "Bool"}, []))
        self.assertEqual(extract_inventory(program('fs.Bool("\\xc3\\xa9\\101", x)')), ({"\u00e9A": "Bool"}, []))
        shapes = ['fs.Bool("a\\qb", x)', 'fs.Bool("\\xff", x)', 'fs.Bool("\\400", x)', 'fs.Bool("\\ud800", x)']
        shapes += ['x := "abc', 'fs.Bool("n", false', "fs.StringVar(&x)", "fs.Bool()"]
        for body in shapes:
            with self.subTest(body=body):
                self.assertEqual(extract_inventory(program(body)), ({}, [("UNSUPPORTED_SHAPE", f"{MAIN_GO}:3")]))

    def test_a5_misleading_input_yields_no_flag(self) -> None:
        cases = {
            "line comment": '// fs.String("x", "", "h")',
            "block comment": '/* fs.String("x", "", "h")\n fs.Bool("y", false, "h") */',
            "help string": 'z := fs.String("real", "", `fs.String("x"`)\n_ = "fs.Int(\\"q\\""',
            "rune quote": "q := '\"'\n_ = q",
        }
        for name, body in cases.items():
            with self.subTest(case=name):
                want = {"real": "String"} if name == "help string" else {}
                self.assertEqual(extract_inventory(program(body)), (want, []))
        outside = 'fs.String("x", "", "h")\n' + program() + '\nfs.Bool("y", false, "h")'
        want = [("UNSUPPORTED_SHAPE", f"{MAIN_GO}:1"), ("UNSUPPORTED_SHAPE", f"{MAIN_GO}:5")]
        self.assertEqual(extract_inventory(outside), ({}, want))
        quiet = '// fs.String("x", "", "h")\n/* fs.Int("q", 0, "h") */\n' + program() + '\n_ = "fs.Bool(\\"y\\""'
        self.assertEqual(extract_inventory(quiet), ({}, []))


class MutationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = read_main()

    def mutated(self, old: str, new: str) -> str:
        self.assertEqual(self.source.count(old), 1, old)
        return self.source.replace(old, new)

    def labels(self, source: str | None = None, classification: dict | None = None, root: Path = ROOT):
        fails = check(root, self.source if source is None else source, classification or EXPECTED)
        self.assertTrue({label for label, _ in fails} <= LABELS)
        for _, where in fails:
            self.assertRegex(where, r"^(--[\w-]+|clients/go/cmd/rubin-node/main\.go(:\d+)?)$")
        return fails

    def insert(self, line: str) -> str:
        return self.mutated("\tif err := fs.Parse(args)", "\t" + line + "\n\tif err := fs.Parse(args)")

    def assert_labels(self, fails: list, *labels: str) -> None:
        self.assertLessEqual(set(labels), {lb for lb, _ in fails}, fails)

    def test_h1_to_h6_source_mutations(self) -> None:
        rename = self.mutated('fs.String("peers",', 'fs.String("peerz",')
        gone = re.sub(r'\tmineExit := fs\.Bool\("mine-exit",[^\n]*\n', "", self.source)
        cases = [
            ("H1", self.insert('fs.Bool("extra-flag", false, "h")'), "MISSING_ROW"),
            ("H2", gone, "STALE_ROW"),
            ("H3", rename, "MISSING_ROW", "STALE_ROW"),
            ("H4", self.insert('fs.Bool("dry-run", false, "h")'), "DUPLICATE_FLAG"),
            ("H5 BoolFunc", self.insert('fs.BoolFunc("x", "h", nil)'), "UNSUPPORTED_SHAPE"),
            ("H5 Int64", self.insert('fs.Int64("x", 0, "h")'), "UNSUPPORTED_SHAPE"),
            ("H5 helper", self.insert("registerExtra(fs)"), "UNSUPPORTED_SHAPE"),
            ("H5 alias", self.insert('g := fs\n\tg.String("a", "", "h")'), "UNSUPPORTED_SHAPE"),
            ("H5 paren", self.insert('(fs).String("a", "", "h")'), "UNSUPPORTED_SHAPE"),
            ("H5 value", self.insert("f := fs.String"), "UNSUPPORTED_SHAPE"),
            ("H5 value arg", self.insert('use(fs.String)\n\tbar("c")'), "UNSUPPORTED_SHAPE"),
            ("H5 value literal", self.insert('x := []any{fs.String}\n\tfoo("b")'), "UNSUPPORTED_SHAPE"),
            ("H5 arg", self.insert('use(fs, String("a", "", "h"))'), "UNSUPPORTED_SHAPE"),
            ("H5 field", self.insert('cfg.fs.String("a", "", "h")'), "UNSUPPORTED_SHAPE"),
            ("H6 identifier", self.insert('fs.String(nameVar, "", "h")'), "DYNAMIC_NAME"),
            ("H6 concat", self.insert('fs.String("a"+"b", "", "h")'), "DYNAMIC_NAME"),
            ("H6 raw", self.insert('fs.String(`x`, "", "h")'), "DYNAMIC_NAME"),
            ("H6 call", self.insert('fs.String(nameFn(), "", "h")'), "DYNAMIC_NAME"),
        ]
        for name, source, *labels in cases:
            with self.subTest(case=name):
                self.assert_labels(self.labels(source), *labels)

    def test_h5_sentinel_lines(self) -> None:
        start, end = START + "flag.ContinueOnError)", "if err := " + PARSE + "; err != nil {"
        lines = self.source.split("\n")
        start_no = 1 + next(i for i, ln in enumerate(lines) if START in ln)
        end_no = 1 + next(i for i, ln in enumerate(lines) if PARSE in ln)
        flagged = {
            "start before": (start, '_ = fs.Bool("y", false, "h"); ' + start, start_no),
            "start after": (start, start + '; fs.Bool("y", false, "h")', start_no),
            "end before": (end, 'if _ = fs.Bool("x", false, "h"); ' + PARSE + " != nil {", end_no),
            "end after": (end, "if err := " + PARSE + "; err != nil || fs.NArg() > 0 {", end_no),
            "end unterminated": (end, end + ' _ = "abc', end_no),
        }
        for name, (old, new, line_no) in flagged.items():
            with self.subTest(case=name):
                self.assertIn(("UNSUPPORTED_SHAPE", f"{MAIN_GO}:{line_no}"), self.labels(self.mutated(old, new)))
        excluded = {
            "start comment": (start, start + ' // fs.Bool("y", false, "h")'),
            "start string": (start, start + '; _ = "fs.Bool(\\"y\\")"'),
            "start block into region": (start, start + ' /* fs.Bool("y", false, "h")\n\tfs.String("q", "", "h") */'),
            "end comment": (end, end + ' /* fs.Bool("z", false, "h") */'),
            "end string": (end, "if err := " + PARSE + '; err != nil && "fs" != "" {'),
        }
        for name, (old, new) in excluded.items():
            with self.subTest(case=name):
                self.assertEqual(self.labels(self.mutated(old, new)), [])

    def test_h5_sentinel_text_not_code(self) -> None:
        start, end = START + "flag.ContinueOnError)", "if err := " + PARSE + "; err != nil {"
        head = '\tfs := flag.NewFlagSet("rubin-node" , flag.ContinueOnError)\n\t_ = fs.Bool("early", false, "h")\n'
        tail = '\n\t_ = fs.Bool("late", false, "h")\n\tif err := fs.Parse(args[0:]); err != nil {'
        cases: dict[str, tuple[str, str, str, int, str | None]] = {}
        contexts = {
            "line comment": "\t// {}",
            "trailing comment": "\t_ = 0 // {}",
            "block same line": "\t/* {} */",
            "block opened on line": "\t/* {}\n\t*/",
            "block closed on line": "\t/*\n\t{} */",
            "block spanning": "\t/*\n\t{}\n\t*/",
            "raw same line": "\t_ = `{}`",
            "raw opened on line": "\t_ = `{}\n\t`",
            "raw opened earlier": "\t_ = `\n\t{}\n\t`",
            "double-quoted": '\t_ = "{}"',
        }
        idents = {"longer identifier": "my", "underscore identifier": "_", "unicode identifier": "\u00e9"}
        for side, line, text in (("start", start, START), ("end", end, PARSE)):
            variants = {k: ctx.format(line) for k, ctx in contexts.items()}
            variants |= {k: "\t" + line.replace("fs", p + "fs", 1) for k, p in idents.items()}
            for k, new in variants.items():
                new = head + new if side == "start" else new + tail
                cases[f"{side} {k}"] = ("\t" + line, new, text, 1, '"early"' if side == "start" else '"late"')
        cases["start second text in comment"] = (start, start + " // " + START, START, 1, None)
        cases["end second text in comment"] = (end, end + " // " + PARSE, PARSE, 1, None)
        cases["end first text in string"] = (end, '_ = "' + PARSE + '"; ' + end, PARSE, 2, None)
        for name, (old, new, text, count, outside) in cases.items():
            with self.subTest(case=name):
                source = self.mutated(old, new)
                extra = [self.line_of(source, outside)] if outside else []
                self.assert_shapes(source, *[self.line_of(source, text)] * count, *extra)

    def line_of(self, source: str, text: str) -> int:
        return 1 + next(i for i, ln in enumerate(source.split("\n")) if text in ln)

    def assert_shapes(self, source: str, *line_nos: int) -> None:
        self.assertEqual(self.labels(source), [("UNSUPPORTED_SHAPE", f"{MAIN_GO}:{n}") for n in line_nos])

    def test_h5_sentinel_after_selector_dot(self) -> None:
        start, end = "\t" + START + "flag.ContinueOnError)", "\tif err := " + PARSE + "; err != nil {"
        respelled = "\n\tif err := fs.Parse(args[0:]); err != nil {"
        starts = {
            "dot": ("\tcfg." + start[1:], True),
            "dot comment": ("\tcfg. /* c */ " + start[1:], True),
            "dot newline": ("\tcfg.\n" + start, True),
            "blank line start": ("\n" + start, False),
            "semicolon": ("\t_ = 0; " + start[1:], False),
            "comma": ("\t_, " + start[1:], False),
            "paren": ("\t_ = (" + start[1:] + ")", False),
            "operator": ("\t_ = !" + start[1:], False),
        }
        ends = {
            "dot": ("\t_ = cfg.fs.Parse(args)", True),
            "dot comment": ("\t_ = cfg./* c */fs.Parse(args)", True),
            "dot newline": ("\t_ = cfg.\n\t\tfs.Parse(args)", True),
            "line start": ("\tfs.Parse(args)", False),
            "operator": ("\t_ = fs.Parse(args)", False),
            "paren": ("\t_ = (fs.Parse(args))", False),
            "comma": ("\t_, _ = 0, fs.Parse(args)", False),
            "brace": ("\tfunc() { fs.Parse(args) }()", False),
        }
        cases = {f"start {k}": (start, new, START, bad) for k, (new, bad) in starts.items()}
        cases |= {f"end {k}": (end, new + respelled, PARSE, bad) for k, (new, bad) in ends.items()}
        for name, (old, new, text, flagged) in cases.items():
            with self.subTest(case=name):
                source = self.mutated(old, new)
                self.assert_shapes(source, *[self.line_of(source, text)] * flagged)

    def test_h5_decoys_and_late_registrations(self) -> None:
        end = "\tif err := " + PARSE + "; err != nil {"
        end_no = self.line_of(self.source, PARSE)
        late = '\n\tfs.Bool("zz-escaped", false, "x")\n\tif err := fs.Parse(args[0:]); err != nil {'
        cases = {
            "selector decoy": (self.mutated(end, "\t_ = cfg.fs.Parse(args)" + late), (end_no, end_no + 1)),
            "function-literal decoy": (
                self.mutated(end, "\t_ = func() error { return fs.Parse(args) }" + late),
                (end_no + 1,),
            ),
            "after end": (self.mutated(end, end + '\n\t\tfs.String("late", "", "h")'), (end_no + 1,)),
        }
        for name, (source, line_nos) in cases.items():
            with self.subTest(case=name):
                self.assert_shapes(source, *line_nos)

    def test_h5_outside_region_sweep(self) -> None:
        start, end = "\t" + START + "flag.ContinueOnError)", "\tif err := " + PARSE + "; err != nil {"
        start_no, end_no = self.line_of(self.source, START), self.line_of(self.source, PARSE)
        last_no = self.source.count("\n") + 2
        positions = {
            "file top": (lambda t: t + "\n" + self.source, 1),
            "before start": (lambda t: self.mutated(start, "\t" + t + "\n" + start), start_no),
            "start line": (lambda t: self.mutated(start, start + "; " + t), start_no),
            "end line": (lambda t: self.mutated(end, "\t_ = " + t + "; " + end[1:]), end_no),
            "after end": (lambda t: self.mutated(end, end + "\n\t" + t), end_no + 1),
            "file end": (lambda t: self.source + "\n" + t, last_no),
        }
        calls = {m: f'fs.{m}("n", x, "h")' if NAME_ARG[m] == 0 else f'fs.{m}(&x, "n", x, "h")' for m in NAME_ARG}
        for (where, (put, line_no)), (method, call) in itertools.product(positions.items(), calls.items()):
            with self.subTest(where=where, method=method):
                self.assert_shapes(put(call), line_no)
        flagged = {
            "spaced": 'fs . String ("late", "", "h")',
            "comment between": 'fs./* c */String("late", "", "h")',
            "multi-line": 'fs.\n\tString(\n\t"late", "", "h")',
            "selector receiver": 'cfg.fs.String("late", "", "h")',
        }
        quiet = {
            "io/fs value": "_ = fs.ErrNotExist",
            "set output": "fs.SetOutput(io.Discard)",
            "parse": "_ = fs.Parse(args[1:])",
            "unsupported method": 'fs.BoolFunc("x", "h", nil)',
            "method value": "f := fs.String",
            "fs argument": 'use(fs, String("a", "", "h"))',
            "longer identifier": 'myfs.String("a", "", "h")',
            "line comment": '// fs.String("a", "", "h")',
            "block comment": '/* fs.Bool("a", false, "h")\n\tfs.Int("b", 0, "h") */',
            "string": '_ = "fs.Int(\\"a\\", 0, \\"h\\")"',
            "raw string": '_ = `fs.Uint("a", 0, "h")`',
        }
        for where in ("before start", "after end"):
            put, line_no = positions[where]
            for name, text in flagged.items():
                with self.subTest(where=where, case=name):
                    self.assert_shapes(put(text), line_no)
            for name, text in quiet.items():
                with self.subTest(where=where, case=name):
                    self.assert_shapes(put(text))
        put_after, put_last = positions["after end"][0], positions["file end"][0]
        unterminated = {
            "string after end": (put_after('_ = "abc'), end_no + 1),
            "string at file end": (put_last('_ = "abc'), last_no),
            "block at file end": (put_last("/* open"), last_no),
            "raw at file end": (put_last("_ = `open"), last_no),
        }
        for name, (source, line_no) in unterminated.items():
            with self.subTest(case="unterminated " + name):
                self.assert_shapes(source, line_no)
        self.assert_shapes(put_last("f := fs.String"))
        self.assert_shapes(put_after('fs.Int("a", 0, "h")\n\t_ = "abc'), end_no + 1, end_no + 2)
        put_before = positions["before start"][0]
        bad_before = put_before('fs.Int("a", 0, "h")\n\t_ = "abc')
        want = [("UNSUPPORTED_SHAPE", f"{MAIN_GO}:{start_no + 1}"), ("UNSUPPORTED_SHAPE", f"{MAIN_GO}:{start_no}")]
        self.assertEqual(extract_inventory(bad_before), ({}, want))

    def test_h7_sentinels_return_only_sentinel(self) -> None:
        cases = {
            "missing start": self.mutated(START, 'fs := flag.NewFlagSet("other", '),
            "duplicate start": self.source + "\n// " + START + "x\n",
            "missing parse": self.mutated("fs.Parse(args)", "fs.Parse(argv)"),
            "duplicate parse": self.source + "\n// " + PARSE + "\n",
            "parse before start": "// " + PARSE + "\n" + self.mutated(PARSE, "fs.Parse(argv)"),
        }
        for name, source in cases.items():
            with self.subTest(case=name):
                fails = self.labels(source)
                self.assertTrue(fails)
                self.assertEqual({label for label, _ in fails}, {"SENTINEL"})

    def with_row(self, flag: str, row: object) -> dict:
        cls = copy.deepcopy(EXPECTED)
        cls[flag] = row
        return cls

    def test_h8_h9_anchor_resolution(self) -> None:
        peer = "TestValidateConfigRejectsBadPeer"
        path_cases = {
            "outside": "conformance/replay_test.go",
            "non-test": "clients/go/node/config.go",
            "missing": "clients/go/node/missing_test.go",
            "escape": "clients/go/../../conformance/replay_test.go",
            "dot-dot prefix": "tools/../clients/go/node/config_test.go",
            "dot prefix": "./clients/go/node/config_test.go",
        }
        for name, path in path_cases.items():
            with self.subTest(case=name):
                self.assert_labels(self.labels(classification=self.with_row("--peers", _anchor(path, peer))), "ANCHOR_PATH")
        absent = _anchor(CFG, "TestNoSuchSymbolInThatFile")
        self.assert_labels(self.labels(classification=self.with_row("--peers", absent)), "ANCHOR_SYMBOL")
        with tempfile.TemporaryDirectory() as tmp:
            twice = Path(tmp, "clients/go")
            twice.mkdir(parents=True)
            twice.joinpath("dup_test.go").write_text("func TestTwice(t *testing.T) {\nfunc TestTwice(t *testing.T) {\n")
            row = self.with_row("--peers", _anchor("clients/go/dup_test.go", "TestTwice"))
            self.assert_labels(self.labels(classification=row, root=Path(tmp)), "ANCHOR_SYMBOL")
            line = "func TestOnce(t *testing.T) {"
            files = {
                "comment only": ("// " + line + "\n", ["ANCHOR_SYMBOL"]),
                "indented only": ("\t" + line + "\n", ["ANCHOR_SYMBOL"]),
                "trailing text only": (line + " }\n", ["ANCHOR_SYMBOL"]),
                "one line plus comment": (line + "\n// " + line + "\n", []),
            }
            for name, (text, want) in files.items():
                with self.subTest(case=name):
                    twice.joinpath("once_test.go").write_text(text)
                    row = {"--peers": _anchor("clients/go/once_test.go", "TestOnce")}
                    fails = [lb for lb, _ in self.labels(classification=row, root=Path(tmp)) if lb.startswith("ANCHOR")]
                    self.assertEqual(fails, want)

    def test_h10_row_shape(self) -> None:
        good = {"path": CFG, "symbol": "TestValidateConfigRejectsBadPeer"}
        rows = {
            "both": {"anchor": good, "reason": REASON},
            "neither": {},
            "extra key": {"anchor": good, "other": 1},
            "empty path": {"anchor": {**good, "path": ""}},
            "empty symbol": {"anchor": {**good, "symbol": ""}},
            "missing path": {"anchor": {"symbol": good["symbol"]}},
            "missing symbol": {"anchor": {"path": CFG}},
            "extra inner key": {"anchor": {**good, "extra": "x"}},
            "non-string": {"anchor": {"path": 1, "symbol": 2}},
            "non-object": {"anchor": "x"},
            "row not object": "x",
        }
        for name, row in rows.items():
            with self.subTest(case=name):
                fails = self.labels(classification=self.with_row("--peers", row))
                self.assertIn(("ROW_SHAPE", "--peers"), fails)
                self.assertNotIn(("ANCHOR_PATH", "--peers"), fails)
                self.assertNotIn(("ANCHOR_SYMBOL", "--peers"), fails)

    def test_h11_reason_validity(self) -> None:
        rows = {
            "non-bool flag": ("--mine-blocks", {"reason": REASON}),
            "unknown code": ("--mine-exit", {"reason": "OPAQUE_VALUE"}),
            "n/a": ("--mine-exit", {"reason": "N/A"}),
            "parse owned": ("--mine-exit", {"reason": "PARSE_OWNED"}),
            "free text": ("--mine-exit", {"reason": "boolean switch, parser only"}),
            "trailing space": ("--mine-exit", {"reason": REASON + " "}),
            "lowercase": ("--mine-exit", {"reason": REASON.lower()}),
            "integer": ("--mine-exit", {"reason": 1}),
            "empty object": ("--mine-exit", {"reason": {}}),
        }
        for name, (flag, row) in rows.items():
            with self.subTest(case=name):
                fails = self.labels(classification=self.with_row(flag, row))
                self.assertIn(("REASON_INVALID", flag), fails)

    def test_h11_bool_var_accepts_reason(self) -> None:
        source = self.insert('fs.BoolVar(&v, "bool-var-flag", false, "h")')
        fails = self.labels(source, self.with_row("--bool-var-flag", {"reason": REASON}))
        self.assertNotIn("REASON_INVALID", {label for label, _ in fails})

    def test_h12_pinned_rows(self) -> None:
        for flag in ("--mine-blocks", "--pv-shadow-max", "--da-mempool-size"):
            with self.subTest(flag=flag):
                cls = copy.deepcopy(EXPECTED)
                del cls[flag]
                fails = self.labels(classification=cls)
                self.assertIn(("MISSING_ROW", flag), fails)
                self.assertIn(("CLASSIFICATION_MISMATCH", flag), fails)
                symbol = TYPED if flag == "--da-mempool-size" else "TestRunDAMempoolSizeFlag"
                swapped = self.labels(classification=self.with_row(flag, _anchor(MAIN_TEST, symbol)))
                self.assertIn(("CLASSIFICATION_MISMATCH", flag), swapped)
        sixth = self.insert('fs.Bool("sixth-bool", false, "h")')
        fails = self.labels(sixth, self.with_row("--sixth-bool", {"reason": REASON}))
        self.assertIn(("CLASSIFICATION_MISMATCH", "--sixth-bool"), fails)
        misplaced = self.with_row("--mine-blocks", {"reason": REASON})
        self.assertIn(("CLASSIFICATION_MISMATCH", "--mine-blocks"), self.labels(classification=misplaced))


if __name__ == "__main__":
    unittest.main()
