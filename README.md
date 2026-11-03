# EnvLens

X-ray a `.env` file before it ships.

## The problem

A `.env` file is where secrets go to leak: a real API key pasted into a
template, credentials baked into a database URL, `DEBUG=true` left on in
production, a placeholder like `changeme` that was never replaced, or a
`.env` that was never added to `.gitignore` and gets committed. Each of
these is a one-line mistake with outsized consequences, and none of them
is caught by a compiler.

## What it does

EnvLens parses a dotenv file and checks it against 20 rules (see below),
then prints a score, a grade, a verdict, and a fix hint for every finding.
It also reports, with `--code-dir`, which keys your code references but
the file does not define (ENV18) and which keys are defined but never
referenced (ENV19). Output formats: coloured text (default), JSON, and a
single self-contained HTML report with severity filters and
click-a-finding-to-highlight-the-source-line.

## Install / build

Requires JDK 21+. Zero shipped dependencies — plain `javac`. JUnit 5 is a
test-only dependency (the console-standalone jar in `lib/`, which is
gitignored and never shipped; download it from Maven Central as
`org.junit.platform:junit-platform-console-standalone:1.11.4` if it is
missing).

```sh
./build.sh
java -jar build/envlens.jar --help
```

## Usage

```sh
envlens <file> [--format text|json|html] [--output PATH]
        [--fail-on critical|warning|info] [--code-dir DIR] [--no-color] [--help]
```

Exit codes: `0` = pass (no findings at or above the `--fail-on`
threshold, default `warning`), `1` = findings at or above the threshold,
`2` = usage or file error (missing file, unreadable file, no arguments,
bad flag, `--code-dir` not a directory).

```sh
# Check a file, print coloured text to stdout
java -jar build/envlens.jar .env

# HTML report, and fail the build on any warning or worse
java -jar build/envlens.jar .env --format html --output report.html

# Also check which keys the code actually uses
java -jar build/envlens.jar .env --code-dir src

# JSON for CI
java -jar build/envlens.jar .env --format json --fail-on critical
```

## Example output

The output below is reproduced verbatim from real runs of the built jar
on the shipped examples (run with `--no-color` so the text pastes cleanly).

`examples/bad.env` (exit code 1):

```
EnvLens report: bad.env
Score: 0/100  Grade: F  Verdict: FAIL
Findings: 19 (critical 5, warning 13, info 1)
[CRITICAL] ENV01 (line 2) AWS_ACCESS_KEY_ID: Value matches a real secret pattern (e.g. cloud key, API token). Fix: Rotate this credential, remove it from the file, and load it from a secrets manager.
[CRITICAL] ENV01 (line 3) STRIPE_SECRET_KEY: Value matches a real secret pattern (e.g. cloud key, API token). Fix: Rotate this credential, remove it from the file, and load it from a secrets manager.
[CRITICAL] ENV01 (line 4) GITHUB_TOKEN: Value matches a real secret pattern (e.g. cloud key, API token). Fix: Rotate this credential, remove it from the file, and load it from a secrets manager.
[CRITICAL] ENV02 (line 5) DATABASE_URL: Credentials embedded in a URL value for 'DATABASE_URL'. Fix: Split the URL into host/port/user/password parts, or use a secrets manager.
[WARNING] ENV07 (line 6) DEBUG: DEBUG is enabled. Fix: Set DEBUG=false (or remove it) before shipping.
[CRITICAL] ENV08 (line 7) NODE_ENV: NODE_ENV=production combined with DEBUG enabled or a placeholder/weak secret. Fix: Disable DEBUG and replace placeholder/weak secrets before a production deploy.
[WARNING] ENV03 (line 8) APP_NAME: Placeholder value for 'APP_NAME'. Fix: Replace it with a real value (in a safe store) or remove the key.
[WARNING] ENV04 (line 9) EMPTY_VALUE: Empty value for 'EMPTY_VALUE'. Fix: Set a value or remove the key if it is unused.
[WARNING] ENV09 (line 10) WEAK_SECRET: Short secret for 'WEAK_SECRET' (under 16 characters). Fix: Use a long randomly generated secret (32+ characters).
[WARNING] ENV10 (line 11) BACKUP_API_KEY: Secret value reused across multiple secret keys. Fix: Give each key its own unique secret.
[WARNING] ENV10 (line 12) SECONDARY_API_KEY: Secret value reused across multiple secret keys. Fix: Give each key its own unique secret.
[WARNING] ENV05 (line 14) DUPLICATE_KEY: Duplicate key 'DUPLICATE_KEY': later definition wins. Fix: Remove the duplicate definition and keep one value.
[WARNING] ENV06 (line 15) lowercase_key: Invalid key name 'lowercase_key': use UPPER_SNAKE_CASE. Fix: Rename the key to UPPER_SNAKE_CASE (letters, digits, underscores).
[WARNING] ENV06 (line 16) bad-key: Invalid key name 'bad-key': use UPPER_SNAKE_CASE. Fix: Rename the key to UPPER_SNAKE_CASE (letters, digits, underscores).
[WARNING] ENV13 (line 17) PORT: PORT value for 'PORT' is not a valid port (1-65535). Fix: Set it to a number between 1 and 65535.
[WARNING] ENV14 (line 18) SECRET_FLAG: Secret-named key 'SECRET_FLAG' holds a bare boolean/number, not a secret. Fix: Rename the key if it is a flag, or set a real secret value.
[WARNING] ENV12 (line 19) UNQUOTED: Unquoted value for 'UNQUOTED' contains spaces. Fix: Quote the value, or remove the spaces.
[INFO] ENV15 (line 20) TRAILING_SPACES: Trailing whitespace on the line for 'TRAILING_SPACES'. Fix: Trim trailing spaces/tabs from the line.
[WARNING] ENV17 (line 21): Malformed line: unbalanced double quote. Fix: Fix the quoting or the key=value shape on this line.
```

`examples/good.env` (exit code 0):

```
EnvLens report: good.env
Score: 100/100  Grade: A  Verdict: CLEAN
Findings: 0 (critical 0, warning 0, info 0)
No findings. Clean.
```

Template files: `examples/bad-template.env.example` scores 40/100, grade D,
verdict FAIL, 4 findings (2 critical, 2 warning) — it triggers ENV11
because it contains a real-looking value. The clean template
`examples/example-template.env.example` scores 90/100, grade A, verdict
NEEDS WORK, 2 findings (both ENV04 empty values) — empty template values
are expected, and it contains no ENV11 finding.

## Rules

| ID | Severity | What it checks |
|----|----------|----------------|
| ENV01 | Critical | Real-looking secret patterns: AWS-style keys, `sk_live_`/`sk_test_` keys, `ghp_`/`github_pat_` tokens, Slack `xoxb-` tokens, Stripe-like keys, and generic high-entropy tokens on secret-named keys |
| ENV02 | Critical | Credentials embedded in a URL value (postgres/mysql/mongodb/redis URL with `user:password@`) |
| ENV03 | Warning | Placeholder values (`changeme`, `your-key-here`, `TODO`, `xxx`, `example`, `replace-me`, `dummy`, `test123`, …) |
| ENV04 | Warning | Empty value |
| ENV05 | Warning | Duplicate key (later definition wins) |
| ENV06 | Warning | Invalid key name (lowercase, spaces, dashes, leading digit) |
| ENV07 | Warning | `DEBUG` enabled (`DEBUG=true`, or any non-empty value other than `false`/`0`) |
| ENV08 | Critical | `NODE_ENV=production` combined with `DEBUG` enabled or a placeholder/weak secret |
| ENV09 | Warning | Short/weak secret (under 16 characters on a secret-named key) |
| ENV10 | Warning | Same secret value reused across 2+ distinct secret keys |
| ENV11 | Critical | Real-looking value inside a `.env.example` / `.env.sample` template file |
| ENV12 | Warning | Unquoted value containing spaces |
| ENV13 | Warning | `PORT` (or `*_PORT`) non-numeric or outside 1–65535 |
| ENV14 | Warning | Secret-named key whose value is a bare boolean or number |
| ENV15 | Info | Trailing whitespace on a line |
| ENV16 | Critical | File not covered by `.gitignore` in its own directory — if no `.gitignore` exists there at all, it is flagged |
| ENV17 | Warning | Unbalanced quotes / malformed line |
| ENV18 | Warning | With `--code-dir`: code references a key not defined in the file |
| ENV19 | Info | With `--code-dir`: key defined but never referenced in the scanned code |
| ENV20 | Info | File mixes Windows (CRLF) and Unix (LF) line endings |

Scoring: start at 100; critical −20 (−25 for ENV01, ENV02, ENV11, ENV16),
warning −5, info −1; floor 0. Grades: 90+ A, 75–89 B, 60–74 C, 40–59 D,
below F. Verdict: any critical → FAIL, else any warning → NEEDS WORK,
else CLEAN.

## Security / masking — read this first

**No output — text, JSON, or HTML — ever prints the value of a
secret-named key or credentials inside a URL value.** Secret values are
replaced with a fixed mask (`••••••••`); the mask never contains
characters from the real value. Non-secret values may be shown. The HTML
report's source preview applies the same masking, so a generated report
is safe to share.

**All example values in this repository are fake.** The examples use
only the AWS documentation example key (`AKIAIOSFODNN7EXAMPLE`), the
database URL `postgres://user:password@localhost:5432/mydb`, and
pattern-shaped fake tokens (`sk_test_example_0000`,
`ghp_example000000000000000000000000000000` style values). Never paste a
real secret into an example, a test, or a report.

`.gitignore` semantics (ENV16): EnvLens looks only at `.gitignore` in
the file's own directory, not at parent directories. A pattern matches
the file's bare name; `*` matches any run of non-`/` characters, `**`
matches anything, a leading `/` is stripped, directory-only patterns
(trailing `/`) do not match a file, and a later `!` negation un-ignores.
The shipped `examples/` directory has its own `.gitignore` covering
`*.env` and `*.env.example`, which is why the shipped examples do not
trigger ENV16; a real `.env` in a directory without such coverage does.

Code-dir languages scanned (ENV18/ENV19): Java (`System.getenv`),
JavaScript/TypeScript (`process.env.X`, `process.env["X"]`), Python
(`os.environ["X"]`, `os.getenv("X")`). Only source extensions
`.java .js .ts .jsx .tsx .py .go .rb .php .rs` are read.

## Parser notes

Blank lines, `#` comments, the `export KEY=...` prefix, unquoted,
single-quoted and double-quoted values (double-quoted values may span
lines), line numbers per entry, and a bare `KEY` with no `=` treated as
empty. Unquoted values strip a trailing ` # comment` only when the `#`
is preceded by whitespace, so `hello#notcomment` keeps its `#`.

## How to run tests

```sh
./build.sh   # compiles, runs the full JUnit 5 suite, then packages the jar
```

57 tests: parser (quotes, `export`, multiline, comments, duplicates,
line numbers), every rule family, scoring/grades, masking (no secret
value string appears in text/JSON/HTML output for a secret fixture),
HTML self-containment (no `src=` attributes, no link tags, no `http`
strings), and CLI exit codes including `--fail-on` and missing files.

## License

MIT — see `LICENSE`.
