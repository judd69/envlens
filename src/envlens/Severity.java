package envlens;

public enum Severity {
    INFO(1), WARNING(2), CRITICAL(3);

    private final int rank;

    Severity(int rank) {
        this.rank = rank;
    }

    public int rank() {
        return rank;
    }

    public static Severity fromName(String name) {
        return switch (name.toLowerCase()) {
            case "critical" -> CRITICAL;
            case "warning" -> WARNING;
            case "info" -> INFO;
            default -> throw new IllegalArgumentException("unknown severity: " + name);
        };
    }
}
