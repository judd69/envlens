package envlens;

import java.util.List;

/**
 * Renders a report. Security invariant for every format: a secret value
 * is never rendered. Findings carry no values at all, and the HTML source
 * preview masks secret values and URL credentials (see maskedSourceLines).
 */
public final class Report {
    private Report() {
    }

    private static final String RESET = "\u001b[0m";
    private static final String RED = "\u001b[31m";
    private static final String YELLOW = "\u001b[33m";
    private static final String CYAN = "\u001b[36m";

    public static String text(Analyzer.ReportData data, boolean color) {
        StringBuilder sb = new StringBuilder();
        sb.append("EnvLens report: ").append(data.envFile.fileName()).append("\n");
        sb.append("Score: ").append(data.score).append("/100  Grade: ").append(data.grade)
                .append("  Verdict: ").append(data.verdict).append("\n");
        sb.append("Findings: ").append(data.findings.size())
                .append(" (critical ").append(data.critical)
                .append(", warning ").append(data.warning)
                .append(", info ").append(data.info).append(")\n");
        if (data.findings.isEmpty()) {
            sb.append("No findings. Clean.\n");
            return sb.toString();
        }
        for (Finding f : data.findings) {
            String sev = f.severity().name();
            if (color) {
                String code = switch (f.severity()) {
                    case CRITICAL -> RED;
                    case WARNING -> YELLOW;
                    case INFO -> CYAN;
                };
                sev = code + sev + RESET;
            }
            sb.append("[").append(sev).append("] ").append(f.id());
            sb.append(" (line ").append(f.line()).append(")");
            if (f.key() != null) {
                sb.append(" ").append(f.key());
            }
            sb.append(": ").append(f.message());
            sb.append(" Fix: ").append(f.fix()).append("\n");
        }
        return sb.toString();
    }

    public static String json(Analyzer.ReportData data) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"file\": ").append(quote(data.envFile.fileName())).append(",\n");
        sb.append("  \"score\": ").append(data.score).append(",\n");
        sb.append("  \"grade\": ").append(quote(data.grade)).append(",\n");
        sb.append("  \"verdict\": ").append(quote(data.verdict)).append(",\n");
        sb.append("  \"counts\": {\"critical\": ").append(data.critical)
                .append(", \"warning\": ").append(data.warning)
                .append(", \"info\": ").append(data.info)
                .append(", \"total\": ").append(data.findings.size()).append("},\n");
        sb.append("  \"findings\": [");
        for (int k = 0; k < data.findings.size(); k++) {
            Finding f = data.findings.get(k);
            if (k > 0) {
                sb.append(",");
            }
            sb.append("\n    {\"id\": ").append(quote(f.id()))
                    .append(", \"severity\": ").append(quote(f.severity().name().toLowerCase()))
                    .append(", \"line\": ").append(f.line())
                    .append(", \"key\": ").append(f.key() == null ? "null" : quote(f.key()))
                    .append(", \"message\": ").append(quote(f.message()))
                    .append(", \"fix\": ").append(quote(f.fix())).append("}");
        }
        sb.append(data.findings.isEmpty() ? "]\n" : "\n  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    /** Masked source lines for the HTML preview: one row per parsed entry. */
    public static List<String> maskedSourceLines(Analyzer.ReportData data) {
        List<String> lines = new java.util.ArrayList<>();
        for (Entry e : data.envFile.entries()) {
            String shown;
            if (e.isSecretKey()) {
                shown = e.key() + "=" + SecretUtil.MASK;
            } else if (SecretUtil.hasUrlCredentials(e.value())) {
                shown = e.key() + "=" + SecretUtil.maskUrl(e.value());
            } else {
                String v = e.value().replace("\n", " ");
                shown = e.key() + "=" + v;
            }
            lines.add(e.line() + "|" + shown);
        }
        return lines;
    }

    public static String html(Analyzer.ReportData data) {
        // Self-contained: inline CSS/JS only, no external assets, no links.
        // Deliberately contains no external address strings at all.
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
        sb.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        sb.append("<title>EnvLens report</title>\n<style>\n");
        sb.append("body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0f172a;color:#f1f5f9;margin:0;padding:24px}");
        sb.append("h1{font-size:28px;margin:0 0 4px} .sub{color:#94a3b8;margin:0 0 20px}");
        sb.append(".score{font-size:44px;font-weight:800;color:#6366f1}");
        sb.append(".finding{border:1px solid #334155;border-radius:10px;padding:12px 14px;margin:8px 0;cursor:pointer;background:#1e293b}");
        sb.append(".finding.active{outline:2px solid #6366f1}");
        sb.append(".critical{border-left:6px solid #ef4444}.warning{border-left:6px solid #f59e0b}.info{border-left:6px solid #38bdf8}");
        sb.append("button{margin:4px;padding:6px 12px;border-radius:8px;border:1px solid #334155;background:#1e293b;color:#f1f5f9;cursor:pointer}");
        sb.append("button.active{background:#6366f1}");
        sb.append(".src{position:relative;background:#020617;border:1px solid #334155;border-radius:10px;padding:12px;font-family:ui-monospace,Menlo,monospace;font-size:13px;overflow:auto}");
        sb.append(".srcline{position:relative;z-index:1;padding:2px 6px;white-space:pre}");
        sb.append("#highlight{position:absolute;left:0;right:0;height:22px;background:rgba(99,102,241,.25);border-radius:6px;transition:top .35s cubic-bezier(.34,1.3,.5,1),height .35s cubic-bezier(.34,1.3,.5,1);z-index:0}");
        sb.append("</style>\n</head>\n<body>\n");
        sb.append("<h1>EnvLens report</h1>\n");
        sb.append("<p class=\"sub\">").append(esc(data.envFile.fileName())).append("</p>\n");
        sb.append("<div class=\"score\">").append(data.score).append("/100</div>\n");
        sb.append("<p>Grade ").append(esc(data.grade)).append(" &middot; Verdict ")
                .append(esc(data.verdict)).append(" &middot; ")
                .append(data.findings.size()).append(" findings (critical ")
                .append(data.critical).append(", warning ").append(data.warning)
                .append(", info ").append(data.info).append(")</p>\n");
        sb.append("<div><button data-filter=\"all\" class=\"active\">All</button>");
        sb.append("<button data-filter=\"critical\">Critical</button>");
        sb.append("<button data-filter=\"warning\">Warning</button>");
        sb.append("<button data-filter=\"info\">Info</button></div>\n");
        sb.append("<div id=\"findings\">\n");
        for (Finding f : data.findings) {
            sb.append("<div class=\"finding ").append(f.severity().name().toLowerCase())
                    .append("\" data-line=\"").append(f.line())
                    .append("\" data-sev=\"").append(f.severity().name().toLowerCase()).append("\">");
            sb.append("<strong>").append(esc(f.id())).append("</strong> ");
            sb.append(esc(f.severity().name())).append(" &middot; line ").append(f.line());
            if (f.key() != null) {
                sb.append(" &middot; ").append(esc(f.key()));
            }
            sb.append("<br>").append(esc(f.message()));
            sb.append("<br><em>Fix: ").append(esc(f.fix())).append("</em></div>\n");
        }
        sb.append("</div>\n<h2>Source preview (secret values masked)</h2>\n");
        sb.append("<div class=\"src\" id=\"preview\"><div id=\"highlight\"></div>\n");
        for (String row : maskedSourceLines(data)) {
            int bar = row.indexOf('|');
            int lineNo = Integer.parseInt(row.substring(0, bar));
            sb.append("<div class=\"srcline\" data-line=\"").append(lineNo).append("\">")
                    .append(esc(row.substring(bar + 1))).append("</div>\n");
        }
        sb.append("</div>\n<script>\n");
        sb.append("const preview=document.getElementById('preview');");
        sb.append("const hl=document.getElementById('highlight');");
        sb.append("function moveTo(line){const el=preview.querySelector('.srcline[data-line=\"'+line+'\"]');");
        sb.append("if(!el)return;hl.style.top=el.offsetTop+'px';hl.style.height=el.offsetHeight+'px';");
        sb.append("el.scrollIntoView({block:'nearest'});}");
        sb.append("document.querySelectorAll('.finding').forEach(function(f){");
        sb.append("f.addEventListener('click',function(){");
        sb.append("document.querySelectorAll('.finding').forEach(function(x){x.classList.remove('active')});");
        sb.append("f.classList.add('active');moveTo(f.dataset.line);});});");
        sb.append("document.querySelectorAll('button[data-filter]').forEach(function(b){");
        sb.append("b.addEventListener('click',function(){");
        sb.append("document.querySelectorAll('button[data-filter]').forEach(function(x){x.classList.remove('active')});");
        sb.append("b.classList.add('active');const want=b.dataset.filter;");
        sb.append("document.querySelectorAll('.finding').forEach(function(f){");
        sb.append("f.style.display=(want==='all'||f.dataset.sev===want)?'':'none';});});});");
        sb.append("moveTo(document.querySelector('.finding')?document.querySelector('.finding').dataset.line:1);");
        sb.append("</script>\n</body>\n</html>\n");
        return sb.toString();
    }

    static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    static String quote(String s) {
        if (s == null) {
            return "null";
        }
        StringBuilder out = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.append("\"").toString();
    }
}
