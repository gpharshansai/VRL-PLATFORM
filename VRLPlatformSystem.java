import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.OutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;
import java.io.File;


public class VRLPlatformSystem {

    private static Map<String, String> profileData = new HashMap<>(); // Store profile data in memory

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/", new StaticFileHandler("."));  // serve files from current folder

        // Define routes
        server.createContext("/login", new LoginHandler());
        server.createContext("/welcome", new WelcomeHandler());
        server.createContext("/join_class", new PageHandler("join_class.html"));
        server.createContext("/video_session", new PageHandler("video_session.html"));
        server.createContext("/profile", new PageHandler("profile.html"));
        server.createContext("/waiting", new PageHandler("waiting.html"));
        server.createContext("/forgot_password", new PageHandler("forgot_password.html"));
        server.createContext("/studentprofile", new StudentProfileHandler()); // Profile page
        server.createContext("/setting", new PageHandler("setting.html"));
        server.createContext("/help", new PageHandler("help.html"));
        server.createContext("/register", new RegistrationHandler()); // Registration context

        server.setExecutor(null); // Default executor
        server.start();
        System.out.println("Server started on port 8080");
    }

    // Login Handler
    static class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                System.out.println("Received POST request at /login");

                InputStream inputStream = exchange.getRequestBody();
                BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
                StringBuilder requestBody = new StringBuilder();
                String line;

                while ((line = reader.readLine()) != null) {
                    requestBody.append(line);
                }

                String[] params = requestBody.toString().split("&");
                String email = "";
                String password = "";

                for (String param : params) {
                    String[] pair = param.split("=");
                    if (pair.length == 2) {
                        String key = pair[0];
                        String value = pair[1];
                        if ("email".equals(key)) {
                            email = java.net.URLDecoder.decode(value, "UTF-8");
                        } else if ("password".equals(key)) {
                            password = java.net.URLDecoder.decode(value, "UTF-8");
                        }
                    }
                }

                // Check credentials
                if ("harshan@gmail.com".equals(email) && "1234 ".equals(password)) {
                    System.out.println("Login successful for: " + email);

                    Path welcomePath = Paths.get("C:/Users/poorn/Desktop/VRL_PLATFORM/welcome.html");
                    if (Files.exists(welcomePath)) {
                        String welcomePage = new String(Files.readAllBytes(welcomePath));
                        exchange.getResponseHeaders().set("Content-Type", "text/html");
                        exchange.sendResponseHeaders(200, welcomePage.length());
                        OutputStream os = exchange.getResponseBody();
                        os.write(welcomePage.getBytes());
                        os.close();
                    } else {
                        String response = "Error: Welcome page not found.";
                        exchange.sendResponseHeaders(404, response.length());
                        OutputStream os = exchange.getResponseBody();
                        os.write(response.getBytes());
                        os.close();
                    }
                } else {
                    String response = "{\"message\": \"Invalid email or password.\"}";
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(401, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        }
    }

    // Welcome Handler
    static class WelcomeHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Path welcomePath = Paths.get("C:/Users/poorn/Desktop/VRL_PLATFORM/welcome.html");
            if (Files.exists(welcomePath)) {
                String welcomePage = new String(Files.readAllBytes(welcomePath));
                exchange.getResponseHeaders().set("Content-Type", "text/html");
                exchange.sendResponseHeaders(200, welcomePage.length());
                OutputStream os = exchange.getResponseBody();
                os.write(welcomePage.getBytes());
                os.close();
            } else {
                String response = "Error: Welcome page not found.";
                exchange.sendResponseHeaders(404, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }
        }
    }

    // Registration Handler
    static class RegistrationHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                System.out.println("Received POST request at /register");

                InputStream inputStream = exchange.getRequestBody();
                BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
                StringBuilder requestBody = new StringBuilder();
                String line;

                while ((line = reader.readLine()) != null) {
                    requestBody.append(line);
                }

                Map<String, String> registrationData = new HashMap<>();
                String[] params = requestBody.toString().split("&");

                for (String param : params) {
                    String[] pair = param.split("=");
                    if (pair.length == 2) {
                        registrationData.put(pair[0], java.net.URLDecoder.decode(pair[1], "UTF-8"));
                    }
                }

                System.out.println("Registration data received: " + registrationData);

                // Store the registration data in profileData
                profileData.putAll(registrationData);

                // Redirect to the profile page after successful registration
                exchange.getResponseHeaders().set("Location", "/studentprofile");
                exchange.sendResponseHeaders(302, -1); // 302 Redirect
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        }
    }

    // Profile Handler
    static class StudentProfileHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if ("POST".equals(exchange.getRequestMethod())) {
                System.out.println("Received POST request at /studentprofile");

                InputStream inputStream = exchange.getRequestBody();
                BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
                StringBuilder requestBody = new StringBuilder();
                String line;

                while ((line = reader.readLine()) != null) {
                    requestBody.append(line);
                }

                // Parse the form data
                String[] params = requestBody.toString().split("&");
                for (String param : params) {
                    String[] pair = param.split("=");
                    if (pair.length == 2) {
                        profileData.put(pair[0], java.net.URLDecoder.decode(pair[1], "UTF-8"));
                    }
                }

                System.out.println("Profile updated data: " + profileData);

                // Redirect to welcome.html after successful profile update
                exchange.getResponseHeaders().set("Location", "/welcome");
                exchange.sendResponseHeaders(302, -1); // 302 Redirect
            } else if ("GET".equals(exchange.getRequestMethod())) {
                Path profilePath = Paths.get("C:/Users/poorn/Desktop/VRL_PLATFORM/studentprofile.html");
                if (Files.exists(profilePath)) {
                    String profilePage = new String(Files.readAllBytes(profilePath));

                    // Dynamically update the profile page with stored profile data
                    for (Map.Entry<String, String> entry : profileData.entrySet()) {
                        profilePage = profilePage.replace("{{" + entry.getKey() + "}}", entry.getValue());
                    }

                    exchange.getResponseHeaders().set("Content-Type", "text/html");
                    exchange.sendResponseHeaders(200, profilePage.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(profilePage.getBytes());
                    os.close();
                } else {
                    String response = "Error: Profile page not found.";
                    exchange.sendResponseHeaders(404, response.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(response.getBytes());
                    os.close();
                }
            } else {
                exchange.sendResponseHeaders(405, -1); // Method Not Allowed
            }
        }
    }

    // Page Handler (For serving static pages like join_class.html, setting.html, etc.)
    static class PageHandler implements HttpHandler {
        private String pageName;

        public PageHandler(String pageName) {
            this.pageName = pageName;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Path pagePath = Paths.get("C:/Users/poorn/Desktop/VRL_PLATFORM/" + pageName);
            if (Files.exists(pagePath)) {
                String pageContent = new String(Files.readAllBytes(pagePath));
                exchange.getResponseHeaders().set("Content-Type", "text/html");
                exchange.sendResponseHeaders(200, pageContent.length());
                OutputStream os = exchange.getResponseBody();
                os.write(pageContent.getBytes());
                os.close();
            } else {
                String response = "Error: Page not found.";
                exchange.sendResponseHeaders(404, response.length());
                OutputStream os = exchange.getResponseBody();
                os.write(response.getBytes());
                os.close();
            }
        }
    }
}
// ---- put this AFTER the last closing brace of VRLPlatformSystem ----

class StaticFileHandler implements HttpHandler {
    private final String baseDir;

    public StaticFileHandler(String baseDir) {
        this.baseDir = baseDir;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        if (path.equals("/")) path = "/login.html"; // default page

        File file = new File(baseDir + path).getCanonicalFile();
        if (!file.exists()) {
            String response = "404 Not Found";
            exchange.sendResponseHeaders(404, response.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes());
            }
            return;
        }

        String mime = Files.probeContentType(file.toPath());
        if (mime == null) mime = "application/octet-stream";
        exchange.getResponseHeaders().set("Content-Type", mime);

        byte[] bytes = Files.readAllBytes(file.toPath());
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}

