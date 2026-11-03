package envlens;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class CliTest {

    static final class Run {
        int code;
        String out;
        String err;
    }

    Run run(String... args) {
        var outBuf = new ByteArrayOutputStream();
        var errBuf = new ByteArrayOutputStream();
        int code = Main.run(args, new PrintStream(outBuf, true, StandardCharsets.UTF_8),
                new PrintStream(errBuf, true, StandardCharsets.UTF_8));
        Run r = new Run();
        r.code = code;
        r.out = outBuf.toString(StandardCharsets.UTF_8);
        r.err = errBuf.toString(StandardCharsets.UTF_8);
        return r;
    }

    Path writeEnv(@TempDir Path dir, String name, String content) throws Exception {
        Files.writeString(dir.resolve(".gitignore"), "*.env\n*.env.example\n");
        Path f = dir.resolve(name);
        Files.writeString(f, content);
        return f;
    }

    @Test
    void noArgsIsExit2(@TempDir Path dir) {
        assertEquals(2, run().code);
    }

    @Test
    void missingFileIsExit2(@TempDir Path dir) {
        Run r = run(dir.resolve("nope.env").toString());
        assertEquals(2, r.code);
    }

    @Test
    void cleanFileIsExit0(@TempDir Path dir) throws Exception {
        Path f = writeEnv(dir, "good.env", "APP_NAME=Demo\nPORT=8080\n");
        Run r = run(f.toString(), "--no-color");
        assertEquals(0, r.code);
        assertTrue(r.out.contains("CLEAN"));
    }

    @Test
    void badFileIsExit1(@TempDir Path dir) throws Exception {
        Path f = writeEnv(dir, "bad.env", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
        assertEquals(1, run(f.toString(), "--no-color").code);
    }

    @Test
    void failOnCriticalPassesWarningOnly(@TempDir Path dir) throws Exception {
        Path f = writeEnv(dir, "w.env", "APP_NAME=changeme\n");
        assertEquals(1, run(f.toString(), "--no-color").code); // default warning
        assertEquals(0, run(f.toString(), "--no-color", "--fail-on", "critical").code);
    }

    @Test
    void failOnInfoFailsInfoOnly(@TempDir Path dir) throws Exception {
        Path f = writeEnv(dir, "i.env", "A=1   \n");
        assertEquals(0, run(f.toString(), "--no-color", "--fail-on", "critical").code);
        assertEquals(1, run(f.toString(), "--no-color", "--fail-on", "info").code);
    }

    @Test
    void jsonFormat(@TempDir Path dir) throws Exception {
        Path f = writeEnv(dir, "good.env", "APP_NAME=Demo\n");
        Run r = run(f.toString(), "--format", "json");
        assertTrue(r.out.trim().startsWith("{"));
        assertTrue(r.out.contains("\"verdict\""));
    }

    @Test
    void htmlFormatToOutputFile(@TempDir Path dir) throws Exception {
        Path f = writeEnv(dir, "good.env", "APP_NAME=Demo\n");
        Path out = dir.resolve("report.html");
        Run r = run(f.toString(), "--format", "html", "--output", out.toString());
        assertEquals(0, r.code);
        String html = Files.readString(out);
        assertFalse(html.contains("src="));
        assertFalse(html.toLowerCase().contains("http"));
    }

    @Test
    void helpIsExit0(@TempDir Path dir) {
        Run r = run("--help");
        assertEquals(0, r.code);
        assertTrue(r.out.contains("Usage"));
    }

    @Test
    void unknownFlagIsExit2(@TempDir Path dir) {
        assertEquals(2, run("--bogus").code);
    }

    @Test
    void badFormatIsExit2(@TempDir Path dir) throws Exception {
        Path f = writeEnv(dir, "good.env", "APP_NAME=Demo\n");
        assertEquals(2, run(f.toString(), "--format", "xml").code);
    }

    @Test
    void missingCodeDirIsExit2(@TempDir Path dir) throws Exception {
        Path f = writeEnv(dir, "good.env", "APP_NAME=Demo\n");
        assertEquals(2, run(f.toString(), "--code-dir", dir.resolve("nope").toString()).code);
    }
}
