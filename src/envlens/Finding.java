package envlens;

public record Finding(String id, Severity severity, int line, String key,
                      String message, String fix) {
}
