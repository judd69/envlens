package envlens;

import java.util.ArrayList;
import java.util.List;

/**
 * dotenv parser. Honest about the format it handles:
 * blank lines, '#' comments, 'export KEY=...' prefix, unquoted,
 * single-quoted and double-quoted values (double-quoted values may span
 * lines), line numbers per entry, and a bare KEY with no '=' as empty.
 * Unquoted values strip a trailing ' # comment' only when the '#'
 * is preceded by whitespace.
 */
public final class Parser {
    private Parser() {
    }

    public static EnvFile parse(String fileName, String content) {
        List<Entry> entries = new ArrayList<>();
        List<EnvFile.Malformed> malformed = new ArrayList<>();

        // Split on \n, keeping track of CRLF vs LF for ENV20.
        String[] rawLines = content.split("\n", -1);
        int crlf = 0, lf = 0;
        for (String raw : rawLines) {
            if (raw.endsWith("\r")) {
                crlf++;
            } else {
                lf++;
            }
        }
        // The trailing split element after a final newline is not a line.
        if (content.endsWith("\n") && rawLines.length > 0) {
            lf = Math.max(0, lf - 1);
        }
        boolean mixed = crlf > 0 && lf > 0;

        int i = 0;
        while (i < rawLines.length) {
            String rawLine = rawLines[i];
            int lineNo = i + 1;
            String line = rawLine.endsWith("\r")
                    ? rawLine.substring(0, rawLine.length() - 1) : rawLine;
            boolean trailingWs = line.endsWith(" ") || line.endsWith("\t");
            String trimmed = line.strip();
            i++;

            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }

            String work = trimmed;
            if (work.startsWith("export ") || work.startsWith("export\t")) {
                work = work.substring("export".length()).stripLeading();
            }
            if (work.equals("export")) {
                malformed.add(new EnvFile.Malformed(lineNo, "bare 'export' with no key"));
                continue;
            }

            int eq = work.indexOf('=');
            String key;
            String rawValue;
            if (eq < 0) {
                // Bare KEY with no '=' is an empty value — unless it is not
                // a single token, in which case it is malformed.
                if (!work.matches("[^\\s=]+")) {
                    malformed.add(new EnvFile.Malformed(lineNo, "malformed line (no '=' and not a single key)"));
                    continue;
                }
                key = work;
                entries.add(new Entry(key, "", lineNo, Entry.QuoteStyle.NONE, trailingWs, false));
                continue;
            }
            key = work.substring(0, eq).strip();
            rawValue = work.substring(eq + 1);
            if (key.isEmpty()) {
                malformed.add(new EnvFile.Malformed(lineNo, "empty key before '='"));
                continue;
            }

            String value = rawValue.stripLeading();
            if (value.startsWith("\"")) {
                // Double-quoted: may span lines until an unescaped closing quote.
                StringBuilder sb = new StringBuilder();
                String rest = value.substring(1);
                boolean closed = false;
                boolean multiline = false;
                while (true) {
                    int close = findUnescapedQuote(rest);
                    if (close >= 0) {
                        sb.append(rest, 0, close);
                        closed = true;
                        break;
                    }
                    if (i >= rawLines.length) {
                        break;
                    }
                    sb.append(rest).append("\n");
                    String next = rawLines[i].endsWith("\r")
                            ? rawLines[i].substring(0, rawLines[i].length() - 1) : rawLines[i];
                    i++;
                    multiline = true;
                    rest = next;
                }
                if (!closed) {
                    malformed.add(new EnvFile.Malformed(lineNo, "unbalanced double quote"));
                    continue;
                }
                entries.add(new Entry(key, unescapeDouble(sb.toString()), lineNo,
                        Entry.QuoteStyle.DOUBLE, trailingWs, multiline));
            } else if (value.startsWith("'")) {
                int close = value.indexOf('\'', 1);
                if (close < 0) {
                    malformed.add(new EnvFile.Malformed(lineNo, "unbalanced single quote"));
                    continue;
                }
                entries.add(new Entry(key, value.substring(1, close), lineNo,
                        Entry.QuoteStyle.SINGLE, trailingWs, false));
            } else {
                // Unquoted: strip a trailing ' # comment' only when the '#'
                // is preceded by whitespace, then trim trailing whitespace.
                String v = value;
                int hash = v.indexOf(" #");
                if (hash >= 0) {
                    v = v.substring(0, hash);
                }
                v = v.stripTrailing();
                entries.add(new Entry(key, v, lineNo, Entry.QuoteStyle.NONE, trailingWs, false));
            }
        }

        String base = fileName == null ? "" : fileName;
        boolean isTemplate = base.endsWith(".example") || base.endsWith(".sample")
                || base.contains(".env.example") || base.contains(".env.sample");
        return new EnvFile(base, entries, malformed, mixed, isTemplate);
    }

    private static int findUnescapedQuote(String s) {
        for (int k = 0; k < s.length(); k++) {
            if (s.charAt(k) == '"' && (k == 0 || s.charAt(k - 1) != '\\')) {
                return k;
            }
        }
        return -1;
    }

    private static String unescapeDouble(String s) {
        return s.replace("\\n", "\n")
                .replace("\\t", "\t")
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
    }
}
