package envlens;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Scans source trees for environment-variable references, for ENV18/ENV19.
 * Languages: Java (System.getenv), JavaScript/TypeScript (process.env),
 * Python (os.environ / os.getenv). Only file extensions listed in
 * SOURCE_EXTENSIONS are read; everything else is skipped.
 */
public final class CodeScanner {
    private CodeScanner() {
    }

    public static final Set<String> SOURCE_EXTENSIONS = Set.of(
            ".java", ".js", ".ts", ".jsx", ".tsx", ".py", ".go", ".rb", ".php", ".rs");

    private static final Pattern JAVA_GETENV = Pattern.compile(
            "System\\.getenv\\(\\s*\"([^\"]+)\"\\s*\\)");
    private static final Pattern JS_DOT = Pattern.compile(
            "process\\.env\\.([A-Za-z0-9_]+)");
    private static final Pattern JS_BRACKET = Pattern.compile(
            "process\\.env\\[\\s*[\"']([^\"']+)[\"']\\s*\\]");
    private static final Pattern PY_BRACKET = Pattern.compile(
            "os\\.environ\\[\\s*[\"']([^\"']+)[\"']\\s*\\]");
    private static final Pattern PY_GET = Pattern.compile(
            "os\\.(?:environ\\.get|getenv)\\(\\s*[\"']([^\"']+)[\"']");

    public static final class ScanResult {
        /** Referenced key -> one file where it was seen (first wins). */
        public final Map<String, String> referenced = new LinkedHashMap<>();
    }

    public static ScanResult scan(Path dir) throws IOException {
        ScanResult result = new ScanResult();
        if (dir == null || !Files.isDirectory(dir)) {
            return result;
        }
        try (Stream<Path> walk = Files.walk(dir)) {
            walk.filter(Files::isRegularFile)
                    .filter(p -> SOURCE_EXTENSIONS.stream()
                            .anyMatch(ext -> p.getFileName().toString().endsWith(ext)))
                    .sorted()
                    .forEach(p -> {
                        try {
                            String text = Files.readString(p);
                            for (Pattern pat : new Pattern[]{JAVA_GETENV, JS_DOT, JS_BRACKET, PY_BRACKET, PY_GET}) {
                                Matcher m = pat.matcher(text);
                                while (m.find()) {
                                    result.referenced.putIfAbsent(m.group(1), p.getFileName().toString());
                                }
                            }
                        } catch (IOException ignored) {
                            // Unreadable source file: skip it, do not fail the scan.
                        }
                    });
        }
        return result;
    }

    public static Set<String> referencedKeys(Path dir) throws IOException {
        return new LinkedHashSet<>(scan(dir).referenced.keySet());
    }
}
