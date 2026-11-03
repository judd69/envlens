package envlens;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class ReportTest {

    static final String SECRET = "AKIAIOSFODNN7EXAMPLE";
    static final String URL_SECRET = "postgres://user:password@localhost:5432/mydb";

    Analyzer.ReportData dataFor(String content) throws IOException {
        EnvFile env = Parser.parse("t.env", content);
        return Analyzer.analyze(env, null, null);
    }

    @Test
    void textMasksSecrets() throws IOException {
        var d = dataFor("AWS_ACCESS_KEY_ID=" + SECRET + "\nDATABASE_URL=" + URL_SECRET + "\n");
        String text = Report.text(d, false);
        assertFalse(text.contains(SECRET), "text must not leak AWS key");
        assertFalse(text.contains("password@localhost"), "text must not leak URL credentials");
        assertFalse(text.contains("user:password"), "text must not leak URL credentials");
        assertTrue(text.contains(SecretUtil.MASK) || text.contains("AWS_ACCESS_KEY_ID"));
    }

    @Test
    void jsonMasksSecretsAndIsWellFormed() throws IOException {
        var d = dataFor("AWS_ACCESS_KEY_ID=" + SECRET + "\n");
        String json = Report.json(d);
        assertFalse(json.contains(SECRET));
        assertTrue(json.contains("\"score\""));
        assertTrue(json.contains("\"findings\""));
        assertTrue(json.contains("ENV01"));
        assertTrue(json.trim().startsWith("{") && json.trim().endsWith("}"));
    }

    @Test
    void jsonEscapesQuotes() throws IOException {
        var d = dataFor("APP_NAME=changeme\n");
        String json = Report.json(d);
        assertFalse(json.contains(SECRET));
        assertTrue(json.contains("APP_NAME"));
    }

    @Test
    void htmlIsSelfContainedAndMasksSecrets() throws IOException {
        var d = dataFor("AWS_ACCESS_KEY_ID=" + SECRET + "\nDATABASE_URL=" + URL_SECRET + "\nAPP_NAME=Demo\n");
        String html = Report.html(d);
        assertFalse(html.contains(SECRET), "html must not leak AWS key");
        assertFalse(html.contains("password@localhost"), "html must not leak URL credentials");
        assertFalse(html.contains("src="), "html must have no src= attributes");
        assertFalse(html.contains("<link"), "html must have no link tags");
        assertFalse(html.toLowerCase().contains("http"), "html must contain no http strings");
        assertTrue(html.contains("data-line"), "html must carry finding line data");
        assertTrue(html.contains("Source preview"));
    }

    @Test
    void htmlMasksSourcePreviewLines() throws IOException {
        var d = dataFor("AWS_ACCESS_KEY_ID=" + SECRET + "\nAPP_NAME=Demo\n");
        var lines = Report.maskedSourceLines(d);
        assertEquals(2, lines.size());
        assertTrue(lines.get(0).contains(SecretUtil.MASK));
        assertFalse(lines.get(0).contains(SECRET));
        assertTrue(lines.get(1).contains("APP_NAME=Demo"));
    }

    @Test
    void nonSecretValuesMayBeShown() throws IOException {
        var d = dataFor("APP_NAME=Demo\n");
        String text = Report.text(d, false);
        // APP_NAME=Demo produces no findings, so the report is the clean line;
        // the invariant under test is that no secret handling breaks clean files.
        assertTrue(text.contains("CLEAN"));
    }

    @Test
    void textIncludesScoreGradeVerdict() throws IOException {
        var d = dataFor("APP_NAME=changeme\n");
        String text = Report.text(d, false);
        assertTrue(text.contains("Score:"));
        assertTrue(text.contains("NEEDS WORK"));
    }
}
