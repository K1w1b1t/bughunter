import java.net.URI;

public class ApiSurfaceInspector {
    public static void main(String[] args) {
        String target = args.length > 0 ? args[0] : "";
        int score = 10;
        if (target.contains("api")) score += 20;
        if (target.contains("auth")) score += 20;
        System.out.println("{\"module\":\"java_api_surface\",\"target\":\"" + target + "\",\"jvm_score\":" + score + "}");
    }
}
