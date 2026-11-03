package envlens;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

class RulesTest {

    /** Analyse content in a temp dir WITH a covering .gitignore, so ENV16 stays out unless tested. */
    static Analyzer.ReportData analyze(@TempDir Path dir, String fileName, String content) throws IOException {
        Files.writeString(dir.resolve(".gitignore"), "*.env\n*.env.example\n*.env.sample\n");
        Path file = dir.resolve(fileName);
        Files.writeString(file, content);
        return Analyzer.analyze(Parser.parse(fileName, content), file, null);
    }

    static Analyzer.ReportData analyzeNoGitignore(@TempDir Path dir, String fileName, String content) throws IOException {
        Path file = dir.resolve(fileName);
        Files.writeString(file, content);
        return Analyzer.analyze(Parser.parse(fileName, content), file, null);
    }

    static Set<String> ids(Analyzer.ReportData d) {
        return d.findings.stream().map(Finding::id).collect(Collectors.toSet());
    }

    @Test
    void env01AwsKey(@TempDir Path dir) throws IOException {
        var d = analyze(dir, "t.env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
        assertTrue(ids(d).contains("ENV01"));
        assertEquals("FAIL", d.verdict);
    }

    @Test
    void env01StripeAndGithub(@TempDir Path dir) throws IOException {
        var d = analyze(dir, "t.env",
                "STRIPE_KEY=sk_live_example0000000000000000\nGITHUB_TOKEN=ghp_example000000000000000000000000000000\n");
        assertEquals(2, d.findings.stream().filter(f -> f.id().equals("ENV01")).count());
    }

    @Test
    void env02UrlCredentials(@TempDir Path dir) throws IOException {
        var d = analyze(dir, "t.env", "DATABASE_URL=postgres://user:password@localhost:5432/mydb\n");
        assertTrue(ids(d).contains("ENV02"));
        var clean = analyze(dir, "u.env", "DATABASE_URL=postgres://localhost:5432/mydb\n");
        assertFalse(ids(clean).contains("ENV02"));
    }

    @Test
    void env03Placeholder(@TempDir Path dir) throws IOException {
        var d = analyze(dir, "t.env", "APP_NAME=changeme\n");
        assertTrue(ids(d).contains("ENV03"));
    }

    @Test
    void env04Empty(@TempDir Path dir) throws IOException {
        var d = analyze(dir, "t.env", "EMPTY_VALUE=\n");
        assertTrue(ids(d).contains("ENV04"));
    }

    @Test
    void env05Duplicate(@TempDir Path dir) throws IOException {
        var d = analyze(dir, "t.env", "A=1\nA=2\n");
        assertTrue(ids(d).contains("ENV05"));
        assertEquals(2, d.findings.stream().filter(f -> f.id().equals("ENV05")).count() == 1 ? 2 : 0); // sanity: one dup finding
        assertEquals(1, d.findings.stream().filter(f -> f.id().equals("ENV05")).count());
    }

    @Test
    void env06InvalidKey(@TempDir Path dir) throws IOException {
        var d = analyze(dir, "t.env", "lowercase_key=1\nbad-key=2\n9START=3\n");
        assertEquals(3, d.findings.stream().filter(f -> f.id().equals("ENV06")).count());
    }

    @Test
    void env07Debug(@TempDir Path dir) throws IOException {
        var d = analyze(dir, "t.env", "DEBUG=true\n");
        assertTrue(ids(d).contains("ENV07"));
        var off = analyze(dir, "u.env", "DEBUG=false\n");
        assertFalse(ids(off).contains("ENV07"));
    }

    @Test
    void env08ProductionPlusDebug(@TempDir Path dir) throws IOException {
        var d = analyze(dir, "t.env", "NODE_ENV=production\nDEBUG=true\n");
        assertTrue(ids(d).contains("ENV08"));
        assertEquals("FAIL", d.verdict);
    }

    @Test
    void env09WeakSecret(@TempDir Path dir) throws IOException {
        var d = analyze(dir, "t.env", "WEAK_SECRET=abc123\n");
        assertTrue(ids(d).contains("ENV09"));
        var strong = analyze(dir, "u.env", "API_SECRET=AVeryLongRandomSecretValue12345\n");
        assertFalse(ids(strong).contains("ENV09"));
    }

    @Test
    void env10ReusedSecret(@TempDir Path dir) throws IOException {
        var d = analyze(dir, "t.env",
                "FIRST_API_KEY=SharedBackupValue2026XYZ\nSECOND_API_KEY=SharedBackupValue2026XYZ\n");
        assertEquals(2, d.findings.stream().filter(f -> f.id().equals("ENV10")).count());
    }

    @Test
    void env11TemplateRealValue(@TempDir Path dir) throws IOException {
        var d = analyze(dir, "bad.env.example", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
        assertTrue(ids(d).contains("ENV11"));
        var clean = analyze(dir, "good.env.example", "API_KEY=\n");
        assertFalse(ids(clean).contains("ENV11"));
    }

    @Test
    void env12UnquotedSpaces(@TempDir Path dir) throws IOException {
        var d = analyze(dir, "t.env", "MSG=hello world\n");
        assertTrue(ids(d).contains("ENV12"));
        var quoted = analyze(dir, "u.env", "MSG=\"hello world\"\n");
        assertFalse(ids(quoted).contains("ENV12"));
    }

    @Test
    void env13Port(@TempDir Path dir) throws IOException {
        var d = analyze(dir, "t.env", "PORT=notaport\n");
        assertTrue(ids(d).contains("ENV13"));
        var big = analyze(dir, "u.env", "PORT=99999\n");
        assertTrue(ids(big).contains("ENV13"));
        var ok = analyze(dir, "v.env", "PORT=8080\n");
        assertFalse(ids(ok).contains("ENV13"));
    }

    @Test
    void env14SecretBoolean(@TempDir Path dir) throws IOException {
        var d = analyze(dir, "t.env", "SECRET_FLAG=true\n");
        assertTrue(ids(d).contains("ENV14"));
    }

    @Test
    void env15TrailingWhitespace(@TempDir Path dir) throws IOException {
        var d = analyze(dir, "t.env", "A=1   \n");
        assertTrue(ids(d).contains("ENV15"));
        assertEquals(Severity.INFO, d.findings.stream().filter(f -> f.id().equals("ENV15")).findFirst().orElseThrow().severity());
    }

    @Test
    void env16NoGitignore(@TempDir Path dir) throws IOException {
        var d = analyzeNoGitignore(dir, "t.env", "A=1\n");
        assertTrue(ids(d).contains("ENV16"));
    }

    @Test
    void env16CoveredByGitignore(@TempDir Path dir) throws IOException {
        var d = analyze(dir, "t.env", "A=1\n");
        assertFalse(ids(d).contains("ENV16"));
    }

    @Test
    void env17Malformed(@TempDir Path dir) throws IOException {
        var d = analyze(dir, "t.env", "A=\"unclosed\n");
        assertTrue(ids(d).contains("ENV17"));
    }

    @Test
    void env20MixedEndings(@TempDir Path dir) throws IOException {
        var d = analyze(dir, "t.env", "A=1\r\nB=2\n");
        assertTrue(ids(d).contains("ENV20"));
    }

    @Test
    void scoringAndGrades() {
        // Score arithmetic is checked via ReportData on a hand-built file.
        EnvFile clean = Parser.parse("t.env", "APP_NAME=Demo\nPORT=8080\n");
        // No file path -> no ENV16; no code dir -> no ENV18/19.
        Analyzer.ReportData d;
        try {
            d = Analyzer.analyze(clean, null, null);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        assertEquals(100, d.score);
        assertEquals("A", d.grade);
        assertEquals("CLEAN", d.verdict);
    }

    @Test
    void gradeBoundariesViaCritical(@TempDir Path dir) throws IOException {
        // One ENV01 critical (-25) -> 75 -> B, verdict FAIL.
        var d = analyze(dir, "t.env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
        assertEquals(75, d.score);
        assertEquals("B", d.grade);
    }

    @Test
    void codeDirReferencedUndefinedAndDefinedUnused(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve(".gitignore"), "*.env\n");
        Path code = dir.resolve("code");
        Files.createDirectories(code);
        Files.writeString(code.resolve("App.java"), "String x = System.getenv(\"MISSING_KEY\");\n");
        Files.writeString(code.resolve("app.js"), "const p = process.env.USED_KEY;\n");
        Path file = dir.resolve("t.env");
        String content = "USED_KEY=abc\nUNUSED_KEY=xyz\n";
        Files.writeString(file, content);
        var d = Analyzer.analyze(Parser.parse("t.env", content), file, code);
        assertTrue(ids(d).contains("ENV18"));
        assertTrue(d.findings.stream().anyMatch(f -> f.id().equals("ENV18") && "MISSING_KEY".equals(f.key())));
        assertTrue(d.findings.stream().anyMatch(f -> f.id().equals("ENV19") && "UNUSED_KEY".equals(f.key())));
        assertFalse(d.findings.stream().anyMatch(f -> f.id().equals("ENV19") && "USED_KEY".equals(f.key())));
    }

    @Test
    void codeDirPythonReferences(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve(".gitignore"), "*.env\n");
        Path code = dir.resolve("code");
        Files.createDirectories(code);
        Files.writeString(code.resolve("app.py"), "import os\nv = os.environ[\"PY_KEY\"]\nw = os.getenv(\"PY_KEY2\")\n");
        Path file = dir.resolve("t.env");
        String content = "PY_KEY=x\n";
        Files.writeString(file, content);
        var d = Analyzer.analyze(Parser.parse("t.env", content), file, code);
        assertTrue(d.findings.stream().anyMatch(f -> f.id().equals("ENV18") && "PY_KEY2".equals(f.key())));
    }
}
