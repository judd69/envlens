package envlens;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * EnvLens CLI.
 * Usage: envlens &lt;file&gt; [--format text|json|html] [--output PATH]
 *        [--fail-on critical|warning|info] [--code-dir DIR] [--no-color] [--help]
 * Exit codes: 0 = pass (no findings at/above the fail-on threshold),
 * 1 = findings at/above threshold, 2 = usage or file error.
 * Default --fail-on is warning, so NEEDS WORK and FAIL both exit 1.
 */
public final class Main {
    private Main() {
    }

    public static void main(String[] args) {
        System.exit(run(args, System.out, System.err));
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        String fileArg = null;
        String format = "text";
        String output = null;
        Severity failOn = Severity.WARNING;
        String codeDir = null;
        boolean noColor = false;

        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if (a.equals("--help") || a.equals("-h")) {
                out.print(usage());
                return 0;
            } else if (a.equals("--no-color")) {
                noColor = true;
            } else if (a.equals("--format") || a.equals("--output")
                    || a.equals("--fail-on") || a.equals("--code-dir")) {
                if (i + 1 >= args.length) {
                    err.println("error: " + a + " needs a value");
                    err.print(usage());
                    return 2;
                }
                String v = args[++i];
                switch (a) {
                    case "--format" -> format = v;
                    case "--output" -> output = v;
                    case "--fail-on" -> {
                        try {
                            failOn = Severity.fromName(v);
                        } catch (IllegalArgumentException e) {
                            err.println("error: --fail-on must be critical, warning, or info");
                            return 2;
                        }
                    }
                    case "--code-dir" -> codeDir = v;
                }
            } else if (a.startsWith("--format=")) {
                format = a.substring("--format=".length());
            } else if (a.startsWith("--output=")) {
                output = a.substring("--output=".length());
            } else if (a.startsWith("--fail-on=")) {
                try {
                    failOn = Severity.fromName(a.substring("--fail-on=".length()));
                } catch (IllegalArgumentException e) {
                    err.println("error: --fail-on must be critical, warning, or info");
                    return 2;
                }
            } else if (a.startsWith("--code-dir=")) {
                codeDir = a.substring("--code-dir=".length());
            } else if (a.startsWith("--")) {
                err.println("error: unknown option " + a);
                err.print(usage());
                return 2;
            } else if (fileArg == null) {
                fileArg = a;
            } else {
                err.println("error: unexpected argument " + a);
                err.print(usage());
                return 2;
            }
        }

        if (fileArg == null) {
            err.println("error: no input file given");
            err.print(usage());
            return 2;
        }
        if (!format.equals("text") && !format.equals("json") && !format.equals("html")) {
            err.println("error: --format must be text, json, or html");
            return 2;
        }
        Path file = Paths.get(fileArg);
        if (!Files.isRegularFile(file)) {
            err.println("error: file not found or not readable: " + fileArg);
            return 2;
        }
        Path codePath = null;
        if (codeDir != null) {
            codePath = Paths.get(codeDir);
            if (!Files.isDirectory(codePath)) {
                err.println("error: --code-dir is not a directory: " + codeDir);
                return 2;
            }
        }

        try {
            String content = Files.readString(file, StandardCharsets.UTF_8);
            EnvFile env = Parser.parse(file.getFileName().toString(), content);
            Analyzer.ReportData data = Analyzer.analyze(env, file, codePath);
            String rendered = switch (format) {
                case "json" -> Report.json(data);
                case "html" -> Report.html(data);
                default -> Report.text(data, !noColor);
            };
            if (output != null) {
                Files.writeString(Paths.get(output), rendered, StandardCharsets.UTF_8);
            } else {
                out.print(rendered);
            }
            for (Finding f : data.findings) {
                if (f.severity().rank() >= failOn.rank()) {
                    return 1;
                }
            }
            return 0;
        } catch (IOException e) {
            err.println("error: could not read file: " + e.getMessage());
            return 2;
        }
    }

    static String usage() {
        return """
                EnvLens — X-ray a .env file before it ships.
                Usage: envlens <file> [--format text|json|html] [--output PATH]
                       [--fail-on critical|warning|info] [--code-dir DIR] [--no-color] [--help]
                Exit codes: 0 pass, 1 findings at/above --fail-on (default warning), 2 usage/file error.
                """;
    }
}
