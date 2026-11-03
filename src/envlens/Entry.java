package envlens;

/** One parsed key/value pair, with the line it started on. */
public record Entry(String key, String value, int line, QuoteStyle quote,
                    boolean trailingWhitespace, boolean multiline) {

    public enum QuoteStyle {
        NONE, SINGLE, DOUBLE
    }

    public boolean isSecretKey() {
        return SecretUtil.isSecretKey(key);
    }
}
