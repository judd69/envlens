package envlens;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

public final class Analyzer {
    private Analyzer() {
    }

    private static final Set<String> PLACEHOLDERS = Set.of(
            "changeme", "change-me", "change_me", "your-key-here", "your_key_here",
            "todo", "xxx", "example", "replace-me", "replace_me", "dummy", "test123",
            "placeholder", "your-api-key", "your-api-key-here", "sample", "xxxx",
            "password123", "admin123");

    private static final Pattern VALID_KEY = Pattern.compile("[A-Z_][A-Z0-9_]*");
    private static final Pattern NUMERIC = Pattern.compile("-?\\d+(\\.\\d+)?");
    private static final Pattern BOOLEAN = Pattern.compile("(?i)true|false|yes|no|on|off");

    public static final class ReportData {
        public final EnvFile envFile;
        public final List<Finding> findings;
        public final int score;
        public final String grade;
        public final String verdict;
        public final int critical;
        public final int warning;
        public final int info;

        ReportData(EnvFile envFile, List<Finding> findings) {
            this.envFile = envFile;
            this.findings = findings;
            int c = 0, w = 0, inf = 0, score = 100;
            for (Finding f : findings) {
                switch (f.severity()) {
                    case CRITICAL -> {
                        c++;
                        score -= (f.id().equals("ENV01") || f.id().equals("ENV02")
                                || f.id().equals("ENV11") || f.id().equals("ENV16")) ? 25 : 20;
                    }
                    case WARNING -> {
                        w++;
                        score -= 5;
                    }
                    case INFO -> {
                        inf++;
                        score -= 1;
                    }
                }
            }
            this.critical = c;
            this.warning = w;
            this.info = inf;
            this.score = Math.max(0, score);
            this.grade = this.score >= 90 ? "A" : this.score >= 75 ? "B"
                    : this.score >= 60 ? "C" : this.score >= 40 ? "D" : "F";
            this.verdict = c > 0 ? "FAIL" : w > 0 ? "NEEDS WORK" : "CLEAN";
        }
    }

    public static ReportData analyze(EnvFile env, Path file, Path codeDir) throws IOException {
        List<Finding> findings = new ArrayList<>();
        List<Entry> entries = env.entries();
        Map<String, Entry> effective = env.effective();

        // ENV17 — malformed lines, straight from the parser.
        for (EnvFile.Malformed m : env.malformed()) {
            findings.add(new Finding("ENV17", Severity.WARNING, m.line(), null,
                    "Malformed line: " + m.detail() + ".",
                    "Fix the quoting or the key=value shape on this line."));
        }

        // ENV05 — duplicates (later definition wins, each later one flagged).
        Set<String> seen = new HashSet<>();
        for (Entry e : entries) {
            if (!seen.add(e.key())) {
                findings.add(new Finding("ENV05", Severity.WARNING, e.line(), e.key(),
                        "Duplicate key '" + e.key() + "': later definition wins.",
                        "Remove the duplicate definition and keep one value."));
            }
        }

        for (Entry e : entries) {
            String key = e.key();
            String value = e.value();
            boolean secret = e.isSecretKey();
            boolean placeholder = PLACEHOLDERS.contains(value.toLowerCase());

            // ENV01 — real-looking secret patterns (or generic high-entropy token).
            if (SecretUtil.looksLikeRealSecret(value)) {
                findings.add(new Finding("ENV01", Severity.CRITICAL, e.line(), key,
                        "Value matches a real secret pattern (e.g. cloud key, API token).",
                        "Rotate this credential, remove it from the file, and load it from a secrets manager."));
            } else if (secret && SecretUtil.looksLikeGenericToken(value)) {
                findings.add(new Finding("ENV01", Severity.CRITICAL, e.line(), key,
                        "High-entropy value on a secret-named key looks like a real token.",
                        "Rotate this credential and load it from a secrets manager."));
            }

            // ENV02 — credentials embedded in a URL.
            if (SecretUtil.hasUrlCredentials(value)) {
                findings.add(new Finding("ENV02", Severity.CRITICAL, e.line(), key,
                        "Credentials embedded in a URL value for '" + key + "'.",
                        "Split the URL into host/port/user/password parts, or use a secrets manager."));
            }

            // ENV03 — placeholder values.
            if (placeholder) {
                findings.add(new Finding("ENV03", Severity.WARNING, e.line(), key,
                        "Placeholder value for '" + key + "'.",
                        "Replace it with a real value (in a safe store) or remove the key."));
            }

            // ENV04 — empty value.
            if (value.isEmpty()) {
                findings.add(new Finding("ENV04", Severity.WARNING, e.line(), key,
                        "Empty value for '" + key + "'.",
                        "Set a value or remove the key if it is unused."));
            }

            // ENV06 — invalid key name.
            if (!VALID_KEY.matcher(key).matches()) {
                findings.add(new Finding("ENV06", Severity.WARNING, e.line(), key,
                        "Invalid key name '" + key + "': use UPPER_SNAKE_CASE.",
                        "Rename the key to UPPER_SNAKE_CASE (letters, digits, underscores)."));
            }

            // ENV07 — DEBUG present and enabled.
            if (key.equals("DEBUG") && !value.isEmpty()
                    && !value.equalsIgnoreCase("false") && !value.equals("0")) {
                findings.add(new Finding("ENV07", Severity.WARNING, e.line(), key,
                        "DEBUG is enabled.",
                        "Set DEBUG=false (or remove it) before shipping."));
            }

            // ENV09 — short / weak secret.
            if (secret && !value.isEmpty() && value.length() < 16
                    && !placeholder && !BOOLEAN.matcher(value).matches() && !NUMERIC.matcher(value).matches()) {
                findings.add(new Finding("ENV09", Severity.WARNING, e.line(), key,
                        "Short secret for '" + key + "' (under 16 characters).",
                        "Use a long randomly generated secret (32+ characters)."));
            }

            // ENV11 — real-looking value inside a template file.
            if (env.isTemplate() && SecretUtil.looksLikeRealSecret(value)) {
                findings.add(new Finding("ENV11", Severity.CRITICAL, e.line(), key,
                        "Template file contains a real-looking secret value for '" + key + "'.",
                        "Replace it with an empty or clearly placeholder value in the template."));
            }

            // ENV12 — unquoted value containing spaces.
            if (e.quote() == Entry.QuoteStyle.NONE && value.contains(" ")) {
                findings.add(new Finding("ENV12", Severity.WARNING, e.line(), key,
                        "Unquoted value for '" + key + "' contains spaces.",
                        "Quote the value, or remove the spaces."));
            }

            // ENV13 — PORT out of range or non-numeric.
            if (key.equals("PORT") || key.endsWith("_PORT")) {
                boolean ok = false;
                try {
                    int port = Integer.parseInt(value);
                    ok = port >= 1 && port <= 65535;
                } catch (NumberFormatException ignored) {
                    ok = false;
                }
                if (!ok) {
                    findings.add(new Finding("ENV13", Severity.WARNING, e.line(), key,
                            "PORT value for '" + key + "' is not a valid port (1-65535).",
                            "Set it to a number between 1 and 65535."));
                }
            }

            // ENV14 — secret-named key holding a bare boolean or number.
            if (secret && (BOOLEAN.matcher(value).matches() || NUMERIC.matcher(value).matches())) {
                findings.add(new Finding("ENV14", Severity.WARNING, e.line(), key,
                        "Secret-named key '" + key + "' holds a bare boolean/number, not a secret.",
                        "Rename the key if it is a flag, or set a real secret value."));
            }

            // ENV15 — trailing whitespace on the entry's line.
            if (e.trailingWhitespace()) {
                findings.add(new Finding("ENV15", Severity.INFO, e.line(), key,
                        "Trailing whitespace on the line for '" + key + "'.",
                        "Trim trailing spaces/tabs from the line."));
            }
        }

        // ENV08 — production + debug / placeholder / weak secret.
        Entry nodeEnv = effective.get("NODE_ENV");
        if (nodeEnv != null && nodeEnv.value().equalsIgnoreCase("production")) {
            Entry debug = effective.get("DEBUG");
            boolean debugOn = debug != null && !debug.value().isEmpty()
                    && !debug.value().equalsIgnoreCase("false") && !debug.value().equals("0");
            boolean weakSecret = entries.stream().anyMatch(en ->
                    en.isSecretKey() && !en.value().isEmpty()
                            && (PLACEHOLDERS.contains(en.value().toLowerCase())
                                    || en.value().length() < 16));
            if (debugOn || weakSecret) {
                findings.add(new Finding("ENV08", Severity.CRITICAL, nodeEnv.line(), "NODE_ENV",
                        "NODE_ENV=production combined with DEBUG enabled or a placeholder/weak secret.",
                        "Disable DEBUG and replace placeholder/weak secrets before a production deploy."));
            }
        }

        // ENV10 — same secret value reused across distinct secret keys.
        Map<String, List<Entry>> byValue = new HashMap<>();
        for (Entry e : entries) {
            if (e.isSecretKey() && !e.value().isEmpty()) {
                byValue.computeIfAbsent(e.value(), k -> new ArrayList<>()).add(e);
            }
        }
        for (List<Entry> group : byValue.values()) {
            Set<String> distinctKeys = new HashSet<>();
            for (Entry e : group) {
                distinctKeys.add(e.key());
            }
            if (distinctKeys.size() >= 2) {
                for (Entry e : group) {
                    findings.add(new Finding("ENV10", Severity.WARNING, e.line(), e.key(),
                            "Secret value reused across multiple secret keys.",
                            "Give each key its own unique secret."));
                }
            }
        }

        // ENV16 — .env not covered by .gitignore in its own directory.
        if (file != null) {
            Path dir = file.toAbsolutePath().getParent();
            Path gitignore = dir == null ? null : dir.resolve(".gitignore");
            if (gitignore == null || !Files.exists(gitignore)) {
                findings.add(new Finding("ENV16", Severity.CRITICAL, 1, null,
                        "No .gitignore exists in the directory of this file, so it may be committed.",
                        "Add a .gitignore in this directory covering this file (e.g. '.env')."));
            } else {
                String baseName = file.getFileName().toString();
                if (!isGitignored(gitignore, baseName)) {
                    findings.add(new Finding("ENV16", Severity.CRITICAL, 1, null,
                            "This file is not covered by .gitignore in its own directory.",
                            "Add a pattern covering this file to .gitignore (e.g. '.env')."));
                }
            }
        }

        // ENV20 — mixed CRLF / LF line endings.
        if (env.mixedLineEndings()) {
            findings.add(new Finding("ENV20", Severity.INFO, 1, null,
                    "File mixes Windows (CRLF) and Unix (LF) line endings.",
                    "Normalise the file to LF line endings."));
        }

        // ENV18 / ENV19 — code references, only when a code directory is given.
        if (codeDir != null) {
            CodeScanner.ScanResult scan = CodeScanner.scan(codeDir);
            Set<String> defined = effective.keySet();
            for (String ref : scan.referenced.keySet()) {
                if (!defined.contains(ref)) {
                    findings.add(new Finding("ENV18", Severity.WARNING, 0, ref,
                            "Code references '" + ref + "' but it is not defined in this file.",
                            "Add the key to the file, or fix the reference in code."));
                }
            }
            for (Entry e : effective.values()) {
                if (!scan.referenced.containsKey(e.key())) {
                    findings.add(new Finding("ENV19", Severity.INFO, e.line(), e.key(),
                            "Key '" + e.key() + "' is defined but never referenced in the scanned code.",
                            "Remove it if it is dead config, or keep it if it is used outside the scanned code."));
                }
            }
        }

        findings.sort((a, b) -> {
            int byLine = Integer.compare(a.line(), b.line());
            if (byLine != 0) {
                return byLine;
            }
            return a.id().compareTo(b.id());
        });
        return new ReportData(env, findings);
    }

    /**
     * Minimal .gitignore matching for a single file in the same directory:
     * blank lines and '#' comments ignored, '!' negation respected
     * (a later negated match un-ignores), '*' matches any run of characters
     * except '/', '**' matches anything, a leading '/' is stripped, and a
     * pattern without a slash matches the bare file name.
     */
    static boolean isGitignored(Path gitignore, String baseName) {
        try {
            boolean ignored = false;
            for (String raw : Files.readAllLines(gitignore)) {
                String pat = raw.strip();
                if (pat.isEmpty() || pat.startsWith("#")) {
                    continue;
                }
                boolean negated = pat.startsWith("!");
                if (negated) {
                    pat = pat.substring(1);
                }
                if (pat.endsWith("/")) {
                    continue; // directory-only pattern: cannot match a file here
                }
                if (pat.startsWith("/")) {
                    pat = pat.substring(1);
                }
                if (matchesPattern(pat, baseName)) {
                    ignored = !negated;
                }
            }
            return ignored;
        } catch (IOException e) {
            return false;
        }
    }

    static boolean matchesPattern(String pat, String name) {
        StringBuilder regex = new StringBuilder("^");
        for (int k = 0; k < pat.length(); k++) {
            char c = pat.charAt(k);
            if (c == '*' && k + 1 < pat.length() && pat.charAt(k + 1) == '*') {
                regex.append(".*");
                k++;
            } else if (c == '*') {
                regex.append("[^/]*");
            } else if (c == '?') {
                regex.append("[^/]");
            } else if ("\\.[]{}()+-^$|".indexOf(c) >= 0) {
                regex.append('\\').append(c);
            } else {
                regex.append(c);
            }
        }
        regex.append("$");
        return Pattern.compile(regex.toString()).matcher(name).matches();
    }
}
