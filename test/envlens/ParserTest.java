package envlens;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ParserTest {

    @Test
    void parsesBasicAndExport() {
        EnvFile f = Parser.parse("test.env", "export FOO=bar\nBAZ=qux\n");
        assertEquals(2, f.entries().size());
        assertEquals("bar", f.entries().get(0).value());
        assertEquals("qux", f.entries().get(1).value());
    }

    @Test
    void skipsCommentsAndBlankLines() {
        EnvFile f = Parser.parse("test.env", "# hi\n\nFOO=1 # comment\n# tail\n");
        assertEquals(1, f.entries().size());
        assertEquals("1", f.entries().get(0).value());
    }

    @Test
    void unquotedStripsTrailingCommentOnlyWithWhitespace() {
        EnvFile f = Parser.parse("test.env", "A=hello # note\nB=hello#notcomment\n");
        assertEquals("hello", f.entries().get(0).value());
        assertEquals("hello#notcomment", f.entries().get(1).value());
    }

    @Test
    void singleQuotesAreLiteral() {
        EnvFile f = Parser.parse("test.env", "A='a # b'\n");
        assertEquals("a # b", f.entries().get(0).value());
        assertEquals(Entry.QuoteStyle.SINGLE, f.entries().get(0).quote());
    }

    @Test
    void doubleQuotesUnescape() {
        EnvFile f = Parser.parse("test.env", "A=\"x\\ny\"\n");
        assertEquals("x\ny", f.entries().get(0).value());
    }

    @Test
    void multilineDoubleQuoted() {
        EnvFile f = Parser.parse("test.env", "A=\"line1\nline2\"\nB=2\n");
        assertEquals("line1\nline2", f.entries().get(0).value());
        assertTrue(f.entries().get(0).multiline());
        assertEquals(2, f.entries().get(1).value().length() == 1 ? 2 : 0); // B parsed after multiline
        assertEquals("2", f.entries().get(1).value());
    }

    @Test
    void bareKeyIsEmpty() {
        EnvFile f = Parser.parse("test.env", "FEATURE_X\n");
        assertEquals("", f.entries().get(0).value());
    }

    @Test
    void lineNumbersTracked() {
        EnvFile f = Parser.parse("test.env", "# c\n\nFOO=1\nBAR=2\n");
        assertEquals(3, f.entries().get(0).line());
        assertEquals(4, f.entries().get(1).line());
    }

    @Test
    void duplicatesKeptInOrder() {
        EnvFile f = Parser.parse("test.env", "A=1\nA=2\n");
        assertEquals(2, f.entries().size());
        assertEquals("2", f.effective().get("A").value());
    }

    @Test
    void unbalancedQuoteIsMalformedNotEntry() {
        EnvFile f = Parser.parse("test.env", "A=\"oops\n");
        assertEquals(0, f.entries().size());
        assertEquals(1, f.malformed().size());
    }

    @Test
    void unbalancedSingleQuoteIsMalformed() {
        EnvFile f = Parser.parse("test.env", "A='oops\n");
        assertEquals(1, f.malformed().size());
    }

    @Test
    void templateDetection() {
        assertTrue(Parser.parse("x.env.example", "A=1\n").isTemplate());
        assertTrue(Parser.parse("x.env.sample", "A=1\n").isTemplate());
        assertFalse(Parser.parse("x.env", "A=1\n").isTemplate());
    }

    @Test
    void mixedLineEndingsDetected() {
        EnvFile f = Parser.parse("test.env", "A=1\r\nB=2\n");
        assertTrue(f.mixedLineEndings());
        EnvFile g = Parser.parse("test.env", "A=1\nB=2\n");
        assertFalse(g.mixedLineEndings());
    }

    @Test
    void trailingWhitespaceRecorded() {
        EnvFile f = Parser.parse("test.env", "A=1   \n");
        assertTrue(f.entries().get(0).trailingWhitespace());
    }
}
