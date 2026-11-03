package envlens;

import java.util.List;

public record EnvFile(String fileName, List<Entry> entries,
                      List<Malformed> malformed,
                      boolean mixedLineEndings, boolean isTemplate) {

    public record Malformed(int line, String detail) {
    }

    /** Effective map: later definitions win, as in most dotenv loaders. */
    public java.util.Map<String, Entry> effective() {
        java.util.Map<String, Entry> map = new java.util.LinkedHashMap<>();
        for (Entry e : entries) {
            map.put(e.key(), e);
        }
        return map;
    }
}
