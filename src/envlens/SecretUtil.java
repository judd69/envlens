package envlens;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Secret detection and masking. This class is the security boundary:
 * no report renderer ever prints a raw secret value — it asks here first.
 */
public final class SecretUtil {
    private SecretUtil() {
    }

    public static final String MASK = "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022";

    private static final Pattern SECRET_KEY = Pattern.compile(
            "SECRET|TOKEN|PASSWORD|PASSWD|PWD|PRIVATE|CREDENTIAL|AUTH|SIGNING|API_?KEY|ACCESS_?KEY");

    // Real-looking secret patterns. Deliberately pattern-only: a value that
    // merely contains the word "secret" is not flagged by this class.
    private static final List<Pattern> REAL_PATTERNS = List.of(
            Pattern.compile("AKIA[0-9A-Z]{16}"),
            Pattern.compile("sk_(live|test)_[A-Za-z0-9_]{8,}"),
            Pattern.compile("ghp_[A-Za-z0-9]{20,}"),
            Pattern.compile("github_pat_[A-Za-z0-9_]{20,}"),
            Pattern.compile("xox[baprs]-[A-Za-z0-9-]{10,}"),
            Pattern.compile("rk_(live|test)_[A-Za-z0-9]{16,}"),
            Pattern.compile("SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}"));

    public static final Pattern URL_CREDENTIALS = Pattern.compile(
            "^(postgres(?:ql)?|mysql|mariadb|mongodb(?:\\+srv)?|redis|amqp)://[^:/\\s]+:[^@\\s]+@",
            Pattern.CASE_INSENSITIVE);

    public static boolean isSecretKey(String key) {
        if (key == null) {
            return false;
        }
        return SECRET_KEY.matcher(key.toUpperCase()).find();
    }

    /** True if the value matches a known real-secret shape (ENV01 / ENV11). */
    public static boolean looksLikeRealSecret(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        for (Pattern p : REAL_PATTERNS) {
            if (p.matcher(value).find()) {
                return true;
            }
        }
        return false;
    }

    /** High-entropy token on a secret-named key, used only as a fallback. */
    public static boolean looksLikeGenericToken(String value) {
        if (value == null || value.length() < 32 || value.contains(" ")) {
            return false;
        }
        int classes = 0;
        if (value.matches(".*[a-z].*")) {
            classes++;
        }
        if (value.matches(".*[A-Z].*")) {
            classes++;
        }
        if (value.matches(".*[0-9].*")) {
            classes++;
        }
        if (value.matches(".*[^A-Za-z0-9].*")) {
            classes++;
        }
        return classes >= 3;
    }

    public static boolean hasUrlCredentials(String value) {
        return value != null && URL_CREDENTIALS.matcher(value).find();
    }

    /**
     * The only safe rendering of a value: secret values and URL credentials
     * become a fixed mask; everything else is returned unchanged.
     * The mask never contains characters from the real value.
     */
    public static String maskValue(String key, String value) {
        if (value == null) {
            return "";
        }
        if (isSecretKey(key) || hasUrlCredentials(value)) {
            return MASK;
        }
        return value;
    }

    /** Mask the credential part of a URL value, keeping scheme/host visible. */
    public static String maskUrl(String value) {
        if (value == null) {
            return "";
        }
        return value.replaceAll("://[^@\\s]+@", "://" + MASK + "@");
    }
}
