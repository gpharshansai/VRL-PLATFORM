import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.*;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.util.*;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.sql.SQLException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.nio.charset.StandardCharsets;

public class VRLPlatformSystem {

    private static final String BASE_DIR = ".";
    private static Map<String, String> profileData = new HashMap<>();

    public static void main(String[] args) throws IOException {
        System.out.println(" Testing database connection...");
        if (DatabaseUtil.canConnect()) {
            System.out.println(" Connected to MySQL successfully!");
            DatabaseUtil.printConfig();
        } else {
            System.out.println("Failed to connect to MySQL!");
        }

        int port = 8080;
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException ignored) {}
        }

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", new StaticFileHandler("."));
        server.createContext("/login", new LoginHandler());
        server.createContext("/register", new RegistrationHandler());
        server.createContext("/welcome", new PageHandler("welcome.html"));
        server.createContext("/forgot_password", new PageHandler("forgot_password.html"));
        server.createContext("/help", new PageHandler("help.html"));
        server.createContext("/setting", new PageHandler("setting.html"));
        server.createContext("/join_class", new PageHandler("join_class.html"));
        server.createContext("/video_session", new PageHandler("video_session.html"));
        server.createContext("/waiting", new PageHandler("waiting.html"));
    server.createContext("/studentprofile", new StudentProfileHandler());
    server.createContext("/teacher_dashboard", new TeacherDashboardHandler());
    server.createContext("/upload_video", new VideoUploadHandler());
    server.createContext("/teacher_login", new TeacherLoginHandler());
    server.createContext("/list_videos", new ListVideosHandler());
    server.createContext("/list_videos_meta", new ListVideosMetaHandler());
   
    server.createContext("/ping", new PingHandler());

        server.setExecutor(null);
        server.start();
        System.out.println("🚀 Server started on http://localhost:" + port);
    }

    
    static class ListVideosHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }

                Path uploadDir = Paths.get(BASE_DIR, "uploads", "videos");
                List<String> files = new ArrayList<>();
                if (Files.exists(uploadDir) && Files.isDirectory(uploadDir)) {
                    try (DirectoryStream<Path> ds = Files.newDirectoryStream(uploadDir)) {
                        for (Path p : ds) {
                            if (Files.isRegularFile(p)) {
                                files.add(p.getFileName().toString());
                            }
                        }
                    }
                }

               
                StringBuilder sb = new StringBuilder();
                sb.append('[');
                boolean first = true;
                for (String f : files) {
                    if (!first) sb.append(',');
                    first = false;
                    String url = "/uploads/videos/" + f.replace("\\", "/");
                    sb.append("{\"name\":\"").append(escapeJson(f)).append("\",\"url\":\"").append(escapeJson(url)).append("\"}");
                }
                sb.append(']');

                byte[] out = sb.toString().getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
                exchange.sendResponseHeaders(200, out.length);
                exchange.getResponseBody().write(out);
                exchange.getResponseBody().close();
            } catch (Throwable t) {
                System.err.println("[ListVideosHandler] " + t.getMessage());
                t.printStackTrace();
                try { exchange.sendResponseHeaders(500, -1); } catch (IOException ignore) {}
            }
        }

        private String escapeJson(String s) {
            return s.replace("\\", "\\\\").replace("\"", "\\\"");
        }
    }

    
    static class ListVideosMetaHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }
                String json = DatabaseUtil.getAllVideosJson();
                byte[] out = json.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
                exchange.sendResponseHeaders(200, out.length);
                exchange.getResponseBody().write(out);
                exchange.getResponseBody().close();
            } catch (Throwable t) {
                System.err.println("[ListVideosMetaHandler] " + t.getMessage());
                t.printStackTrace();
                try { exchange.sendResponseHeaders(500, -1); } catch (IOException ignore) {}
            }
        }
    }

    
    static class TeacherDashboardHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                
                String email = getCookie(exchange, "user");
                if (email == null || !"teacher".equals(DatabaseUtil.getUserRole(email))) {
                    String resp = "Forbidden: teacher access required";
                    byte[] rb = resp.getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                    exchange.sendResponseHeaders(403, rb.length);
                    exchange.getResponseBody().write(rb);
                    exchange.getResponseBody().close();
                    return;
                }
                if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                    Path p = Paths.get(BASE_DIR, "teacher_dashboard.html");
                    if (Files.exists(p)) {
                        String page = Files.readString(p);
                        byte[] bytes = page.getBytes(StandardCharsets.UTF_8);
                        exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
                        exchange.sendResponseHeaders(200, bytes.length);
                        exchange.getResponseBody().write(bytes);
                    } else {
                        String resp = "Teacher dashboard not found.";
                        byte[] rb = resp.getBytes(StandardCharsets.UTF_8);
                        exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                        exchange.sendResponseHeaders(404, rb.length);
                        exchange.getResponseBody().write(rb);
                    }
                    exchange.getResponseBody().close();
                    return;
                } else {
                    exchange.sendResponseHeaders(405, -1);
                }
            } catch (Throwable t) {
                System.err.println("[TeacherDashboardHandler] " + t.getMessage());
                t.printStackTrace();
                try { exchange.sendResponseHeaders(500, -1); } catch (IOException ignore) {}
            }
        }
    }

    static class VideoUploadHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
           
            String emailForUpload = getCookie(exchange, "user");
            if (emailForUpload == null || !"teacher".equals(DatabaseUtil.getUserRole(emailForUpload))) {
                exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                byte[] rb = "Forbidden: teacher access required".getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(403, rb.length);
                exchange.getResponseBody().write(rb);
                exchange.getResponseBody().close();
                return;
            }

            if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            String contentType = exchange.getRequestHeaders().getFirst("Content-type");
            if (contentType == null || !contentType.contains("multipart/form-data")) {
                String resp = "Expected multipart/form-data";
                byte[] rb = resp.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                exchange.sendResponseHeaders(400, rb.length);
                exchange.getResponseBody().write(rb);
                exchange.getResponseBody().close();
                return;
            }

            
            String boundary = null;
            String[] parts = contentType.split(";");
            for (String p : parts) {
                p = p.trim();
                if (p.startsWith("boundary=")) {
                    boundary = p.substring("boundary=".length());
                    if (boundary.startsWith("\"") && boundary.endsWith("\"")) {
                        boundary = boundary.substring(1, boundary.length()-1);
                    }
                }
            }
            if (boundary == null) {
                String resp = "Missing boundary in Content-Type";
                byte[] rb = resp.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                exchange.sendResponseHeaders(400, rb.length);
                exchange.getResponseBody().write(rb);
                exchange.getResponseBody().close();
                return;
            }

            byte[] bodyBytes = exchange.getRequestBody().readAllBytes();
            String body = new String(bodyBytes, StandardCharsets.ISO_8859_1);
            String[] partsArr = body.split("--" + boundary);

            Map<String, String> formFields = new HashMap<>();
            String savedFilename = null;

            
            Path uploadDir = Paths.get(BASE_DIR, "uploads", "videos");
            Files.createDirectories(uploadDir);

            for (String part : partsArr) {
                if (part == null || part.trim().isEmpty() || part.equals("--") ) continue;
                int idx = part.indexOf("\r\n\r\n");
                if (idx < 0) continue;
                String headersPart = part.substring(0, idx);
                String dataPart = part.substring(idx + 4);

               
                String cd = null;
                for (String hline : headersPart.split("\r\n")) {
                    if (hline.toLowerCase().startsWith("content-disposition:")) {
                        cd = hline.substring(hline.indexOf(":") + 1).trim();
                        break;
                    }
                }
                if (cd == null) continue;

               
                String name = null;
                String filename = null;
                String[] cdParts = cd.split(";");
                for (String cp : cdParts) {
                    cp = cp.trim();
                    if (cp.startsWith("name=")) {
                        name = cp.substring(5).trim();
                        if (name.startsWith("\"") && name.endsWith("\"")) name = name.substring(1, name.length()-1);
                    } else if (cp.startsWith("filename=")) {
                        filename = cp.substring(9).trim();
                        if (filename.startsWith("\"") && filename.endsWith("\"")) filename = filename.substring(1, filename.length()-1);
                    }
                }

                if (filename != null && !filename.isEmpty()) {
                    
                    String trimmed = dataPart;
                    if (trimmed.endsWith("\r\n")) trimmed = trimmed.substring(0, trimmed.length()-2);

                    byte[] fileBytes = trimmed.getBytes(StandardCharsets.ISO_8859_1);
                    
                    String safeName = System.currentTimeMillis() + "_" + Paths.get(filename).getFileName().toString();
                    Path out = uploadDir.resolve(safeName);
                    Files.write(out, fileBytes);
                    savedFilename = out.toString().replace("\\", "/");
                    System.out.println("Saved uploaded video: " + out.toString());
                } else if (name != null) {
                   
                    String value = dataPart;
                    if (value.endsWith("\r\n")) value = value.substring(0, value.length()-2);
                    formFields.put(name, value);
                }
            }

            if (savedFilename != null) {
                
                String title = formFields.getOrDefault("title", null);
                String course = formFields.getOrDefault("course", null);
                String chapter = formFields.getOrDefault("chapter", null);
                String session = formFields.getOrDefault("session", null);
                String mode = formFields.getOrDefault("mode", null);
                boolean mdSaved = DatabaseUtil.saveVideoMetadata(savedFilename, title, course, chapter, session, mode, emailForUpload);
                String response = "Upload successful. File saved to: " + savedFilename + (mdSaved ? " (metadata saved)" : " (metadata NOT saved)");
                byte[] rb = response.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                exchange.sendResponseHeaders(200, rb.length);
                exchange.getResponseBody().write(rb);
            } else {
                String response = "No file uploaded.";
                byte[] rb = response.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                exchange.sendResponseHeaders(400, rb.length);
                exchange.getResponseBody().write(rb);
            }
            exchange.getResponseBody().close();
        }
    }

    static class PingHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            byte[] resp = "pong".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
            exchange.sendResponseHeaders(200, resp.length);
            exchange.getResponseBody().write(resp);
            exchange.getResponseBody().close();
        }
    }

   
    private static String getCookie(HttpExchange exchange, String key) {
        List<String> cookies = exchange.getRequestHeaders().get("Cookie");
        if (cookies == null) return null;
        for (String header : cookies) {
            String[] pairs = header.split(";");
            for (String p : pairs) {
                String[] kv = p.trim().split("=", 2);
                if (kv.length == 2 && kv[0].equals(key)) {
                    try {
                        return URLDecoder.decode(kv[1], StandardCharsets.UTF_8.toString());
                    } catch (UnsupportedEncodingException e) {
                        return kv[1];
                    }
                }
            }
        }
        return null;
    }

   
    private static void logLoginAttempt(String email, boolean success, HttpExchange exchange) {
        String ip = null;
        String ua = null;
        try {
            if (exchange.getRemoteAddress() != null && exchange.getRemoteAddress().getAddress() != null) {
                ip = exchange.getRemoteAddress().getAddress().getHostAddress();
            }
            ua = exchange.getRequestHeaders().getFirst("User-Agent");
        } catch (Throwable ignore) {}

        
        Integer userId = null;
        String findSql = "SELECT id FROM users WHERE email = ? LIMIT 1";
        String insertSql = "INSERT INTO login_audit (user_id, email, success, ip, user_agent) VALUES (?, ?, ?, ?, ?)";
        try (java.sql.Connection conn = DatabaseUtil.getConnection()) {
            try (java.sql.PreparedStatement ps = conn.prepareStatement(findSql)) {
                ps.setString(1, email);
                try (java.sql.ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) userId = rs.getInt(1);
                }
            }
            try (java.sql.PreparedStatement ps2 = conn.prepareStatement(insertSql)) {
                if (userId != null) ps2.setInt(1, userId); else ps2.setNull(1, java.sql.Types.INTEGER);
                ps2.setString(2, email);
                ps2.setInt(3, success ? 1 : 0);
                ps2.setString(4, ip);
                ps2.setString(5, ua);
                ps2.executeUpdate();
            }
        } catch (Exception e) {
            System.err.println("[logLoginAttempt] failed to record login attempt for " + email + ": " + e.getMessage());
        }
    }

   
    static class LoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                System.out.println("[LoginHandler] " + exchange.getRequestMethod() + " " + exchange.getRequestURI());
                if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(exchange.getRequestBody()));
                    StringBuilder requestBody = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) requestBody.append(line);

                    Map<String, String> formData = parseFormData(requestBody.toString());
                    String email = formData.getOrDefault("email", "");
                    String password = formData.getOrDefault("password", "");

                    if (DatabaseUtil.validateLogin(email, password)) {
                        System.out.println("Login success for " + email);
                        
                        logLoginAttempt(email, true, exchange);
                       
                        String role = DatabaseUtil.getUserRole(email);
                        exchange.getResponseHeaders().add("Set-Cookie", "user=" + URLEncoder.encode(email, StandardCharsets.UTF_8.toString()) + "; Path=/");
                        
                        exchange.getResponseHeaders().add("Set-Cookie", "role=" + URLEncoder.encode(role, StandardCharsets.UTF_8.toString()) + "; Path=/");
                        
                        if ("teacher".equalsIgnoreCase(role)) {
                            exchange.getResponseHeaders().add("Location", "/teacher_dashboard");
                            exchange.sendResponseHeaders(302, -1);
                        } else {
                            Path welcomePath = Paths.get(BASE_DIR, "welcome.html");
                            if (Files.exists(welcomePath)) {
                                String content = Files.readString(welcomePath);
                                byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
                                exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
                                exchange.sendResponseHeaders(200, bytes.length);
                                exchange.getResponseBody().write(bytes);
                            } else {
                                String error = "Welcome page not found.";
                                byte[] eb = error.getBytes(StandardCharsets.UTF_8);
                                exchange.sendResponseHeaders(404, eb.length);
                                exchange.getResponseBody().write(eb);
                            }
                        }
                    } else {
                        
                        logLoginAttempt(email, false, exchange);
                        String error = "<h3>Invalid email or password. Please try again.</h3>";
                        byte[] eb = error.getBytes(StandardCharsets.UTF_8);
                        exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
                        exchange.sendResponseHeaders(401, eb.length);
                        exchange.getResponseBody().write(eb);
                    }
                    exchange.getResponseBody().close();
                } else {
                    
                    Path loginPath = Paths.get(BASE_DIR, "login.html");
                    if (Files.exists(loginPath)) {
                        String page = Files.readString(loginPath);
                        byte[] bytes = page.getBytes(StandardCharsets.UTF_8);
                        exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
                        exchange.sendResponseHeaders(200, bytes.length);
                        exchange.getResponseBody().write(bytes);
                    } else {
                        String error = "Login page not found.";
                        byte[] eb = error.getBytes(StandardCharsets.UTF_8);
                        exchange.sendResponseHeaders(404, eb.length);
                        exchange.getResponseBody().write(eb);
                    }
                    exchange.getResponseBody().close();
                }
            } catch (Throwable t) {
                System.err.println("[LoginHandler] Exception while handling request: " + t.getMessage());
                t.printStackTrace();
                try {
                    String resp = "Internal server error";
                    exchange.getResponseHeaders().add("Content-Type", "text/plain");
                    exchange.sendResponseHeaders(500, resp.length());
                    exchange.getResponseBody().write(resp.getBytes());
                    exchange.getResponseBody().close();
                } catch (IOException ignore) {}
            }
        }
    }

    
    static class TeacherLoginHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                    Path p = Paths.get(BASE_DIR, "teacher_login.html");
                    if (Files.exists(p)) {
                        String page = Files.readString(p);
                        byte[] bytes = page.getBytes(StandardCharsets.UTF_8);
                        exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
                        exchange.sendResponseHeaders(200, bytes.length);
                        exchange.getResponseBody().write(bytes);
                    } else {
                        String resp = "Teacher login page not found.";
                        byte[] rb = resp.getBytes(StandardCharsets.UTF_8);
                        exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                        exchange.sendResponseHeaders(404, rb.length);
                        exchange.getResponseBody().write(rb);
                    }
                    exchange.getResponseBody().close();
                    return;
                }

                if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(exchange.getRequestBody()));
                    StringBuilder requestBody = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) requestBody.append(line);
                    Map<String, String> formData = parseFormData(requestBody.toString());
                    String email = formData.getOrDefault("email", "");
                    String password = formData.getOrDefault("password", "");

                    if (DatabaseUtil.validateLogin(email, password)) {
                       
                        logLoginAttempt(email, true, exchange);
                        String role = DatabaseUtil.getUserRole(email);
                        if (!"teacher".equals(role)) {
                            String resp = "Unauthorized: teacher account required.";
                            byte[] rb = resp.getBytes(StandardCharsets.UTF_8);
                            exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                            exchange.sendResponseHeaders(403, rb.length);
                            exchange.getResponseBody().write(rb);
                            exchange.getResponseBody().close();
                            return;
                        }

                        exchange.getResponseHeaders().add("Set-Cookie", "user=" + URLEncoder.encode(email, StandardCharsets.UTF_8.toString()) + "; Path=/");
                        exchange.getResponseHeaders().add("Set-Cookie", "role=" + URLEncoder.encode(role, StandardCharsets.UTF_8.toString()) + "; Path=/");
                        Path dashboard = Paths.get(BASE_DIR, "teacher_dashboard.html");
                        if (Files.exists(dashboard)) {
                            String content = Files.readString(dashboard);
                            byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
                            exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
                            exchange.sendResponseHeaders(200, bytes.length);
                            exchange.getResponseBody().write(bytes);
                        } else {
                            String resp = "Teacher dashboard not found.";
                            byte[] rb = resp.getBytes(StandardCharsets.UTF_8);
                            exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                            exchange.sendResponseHeaders(404, rb.length);
                            exchange.getResponseBody().write(rb);
                        }
                        exchange.getResponseBody().close();
                        return;
                    } else {
                        
                        logLoginAttempt(email, false, exchange);
                        String resp = "Invalid email or password.";
                        byte[] rb = resp.getBytes(StandardCharsets.UTF_8);
                        exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                        exchange.sendResponseHeaders(401, rb.length);
                        exchange.getResponseBody().write(rb);
                        exchange.getResponseBody().close();
                        return;
                    }
                }
                exchange.sendResponseHeaders(405, -1);
            } catch (Throwable t) {
                System.err.println("[TeacherLoginHandler] " + t.getMessage());
                t.printStackTrace();
                try { exchange.sendResponseHeaders(500, -1); } catch (IOException ignore) {}
            }
        }
    }

    
    static class RegistrationHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                System.out.println("[RegistrationHandler] " + exchange.getRequestMethod() + " " + exchange.getRequestURI());
                if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    
                    System.out.println("[RegistrationHandler] Request headers:");
                    exchange.getRequestHeaders().forEach((k,v) -> System.out.println("  " + k + ": " + String.join(",", v)));

                   
                    BufferedReader reader = new BufferedReader(new InputStreamReader(exchange.getRequestBody()));
                    StringBuilder requestBody = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) requestBody.append(line);
                    System.out.println("[RegistrationHandler] Raw body: " + requestBody.toString());

                    Map<String, String> registrationData = parseFormData(requestBody.toString());
                    System.out.println("📝 Registration data: " + registrationData);

                    boolean saved = false;
                    try {
                        saved = DatabaseUtil.saveRegistration(registrationData);
                        System.out.println("DB save result: " + saved);
                    } catch (SQLException sqle) {
                        System.err.println("[RegistrationHandler] SQLException while saving registration: " + sqle.getMessage());
                        sqle.printStackTrace();
                        
                        if (sqle instanceof SQLIntegrityConstraintViolationException
                                || (sqle.getMessage() != null && sqle.getMessage().toLowerCase().contains("duplicate"))) {
                            String response = "Email already registered.";
                            byte[] rb = response.getBytes(StandardCharsets.UTF_8);
                            exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                            exchange.sendResponseHeaders(409, rb.length);
                            exchange.getResponseBody().write(rb);
                            exchange.getResponseBody().close();
                            return;
                        }

                        String response = "Registration failed due to database error: " + sqle.getMessage();
                        byte[] rb = response.getBytes(StandardCharsets.UTF_8);
                        exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                        exchange.sendResponseHeaders(500, rb.length);
                        exchange.getResponseBody().write(rb);
                        exchange.getResponseBody().close();
                        return;
                    }

                    if (saved) {
                       
                        String role = registrationData.getOrDefault("role", "student");
                        String email = registrationData.getOrDefault("email", "");
                        if ("teacher".equalsIgnoreCase(role)) {
                           
                            try {
                                exchange.getResponseHeaders().add("Set-Cookie", "user=" + URLEncoder.encode(email, StandardCharsets.UTF_8.toString()) + "; Path=/");
                                exchange.getResponseHeaders().add("Set-Cookie", "role=teacher; Path=/");
                            } catch (Exception ignore) {}
                            exchange.getResponseHeaders().add("Location", "/teacher_dashboard");
                            exchange.sendResponseHeaders(302, -1);
                            exchange.getResponseBody().close();
                            return;
                        } else {
                            
                            String redirectUrl = "/login";
                            if (email != null && !email.isEmpty()) {
                                try {
                                    redirectUrl += "?email=" + URLEncoder.encode(email, StandardCharsets.UTF_8.toString());
                                } catch (Exception e) {
                                    redirectUrl += "?email=" + email;
                                }
                            }
                            exchange.getResponseHeaders().add("Location", redirectUrl);
                            exchange.sendResponseHeaders(302, -1);
                            exchange.getResponseBody().close();
                            return;
                        }
                    } else {
                        String response = "Registration failed. Please try again.";
                        byte[] rb = response.getBytes(StandardCharsets.UTF_8);
                        exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                        exchange.sendResponseHeaders(500, rb.length);
                        exchange.getResponseBody().write(rb);
                    }
                    exchange.getResponseBody().close();
                } else if ("GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                    Path registerPath = Paths.get(BASE_DIR, "register.html");
                    if (Files.exists(registerPath)) {
                        String page = Files.readString(registerPath);
                        byte[] bytes = page.getBytes(StandardCharsets.UTF_8);
                        exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
                        exchange.sendResponseHeaders(200, bytes.length);
                        exchange.getResponseBody().write(bytes);
                    } else {
                        String response = "Register page not found.";
                        byte[] rb = response.getBytes(StandardCharsets.UTF_8);
                        exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                        exchange.sendResponseHeaders(404, rb.length);
                        exchange.getResponseBody().write(rb);
                    }
                    exchange.getResponseBody().close();
                } else {
                    exchange.sendResponseHeaders(405, -1);
                }
            } catch (Throwable t) {
                System.err.println("[RegistrationHandler] Exception while handling request: " + t.getMessage());
                t.printStackTrace();
                try {
                    String resp = "Internal server error";
                    byte[] rb = resp.getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                    exchange.sendResponseHeaders(500, rb.length);
                    exchange.getResponseBody().write(rb);
                    exchange.getResponseBody().close();
                } catch (IOException ignore) {}
            }
        }
    }

   
    static class PageHandler implements HttpHandler {
        private final String pageName;
        public PageHandler(String pageName) { this.pageName = pageName; }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            Path path = Paths.get(BASE_DIR, pageName);
                if (Files.exists(path)) {
                    String content = Files.readString(path);
                    byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
                    exchange.sendResponseHeaders(200, bytes.length);
                    exchange.getResponseBody().write(bytes);
                } else {
                    String response = "Page not found.";
                    byte[] rb = response.getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                    exchange.sendResponseHeaders(404, rb.length);
                    exchange.getResponseBody().write(rb);
                }
            exchange.getResponseBody().close();
        }
    }

    
    static class StudentProfileHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                String method = exchange.getRequestMethod();
                if ("GET".equalsIgnoreCase(method)) {
                    Path registerPath = Paths.get(BASE_DIR, "studentprofile.html");
                    if (Files.exists(registerPath)) {
                        String page = Files.readString(registerPath);
                        byte[] bytes = page.getBytes(StandardCharsets.UTF_8);
                        exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
                        exchange.sendResponseHeaders(200, bytes.length);
                        exchange.getResponseBody().write(bytes);
                    } else {
                        String response = "Student profile page not found.";
                        byte[] rb = response.getBytes(StandardCharsets.UTF_8);
                        exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                        exchange.sendResponseHeaders(404, rb.length);
                        exchange.getResponseBody().write(rb);
                    }
                    exchange.getResponseBody().close();
                    return;
                } else if ("POST".equalsIgnoreCase(method)) {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(exchange.getRequestBody()));
                    StringBuilder requestBody = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) requestBody.append(line);
                    Map<String, String> formData = parseFormData(requestBody.toString());

                    String email = formData.getOrDefault("email", "");
                    String newPassword = formData.getOrDefault("password", "");

                    boolean anyUpdated = false;
                    if (newPassword != null && !newPassword.isEmpty() && email != null && !email.isEmpty()) {
                        try {
                            boolean ok = DatabaseUtil.updatePassword(email, newPassword);
                            anyUpdated = anyUpdated || ok;
                            System.out.println("[StudentProfileHandler] updatePassword result: " + ok + " for " + email);
                        } catch (Exception e) {
                            System.err.println("[StudentProfileHandler] Failed to update password: " + e.getMessage());
                        }
                    }

                    

                    if (anyUpdated) {
                        
                        String redirect = "/studentprofile?updated=true";
                        exchange.getResponseHeaders().add("Location", redirect);
                        exchange.sendResponseHeaders(302, -1);
                        exchange.getResponseBody().close();
                        return;
                    } else {
                        String resp = "No changes were applied.";
                        byte[] rb = resp.getBytes(StandardCharsets.UTF_8);
                        exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                        exchange.sendResponseHeaders(200, rb.length);
                        exchange.getResponseBody().write(rb);
                        exchange.getResponseBody().close();
                        return;
                    }
                } else {
                    exchange.sendResponseHeaders(405, -1);
                }
            } catch (Throwable t) {
                System.err.println("[StudentProfileHandler] Exception while handling request: " + t.getMessage());
                t.printStackTrace();
                try {
                    String resp = "Internal server error";
                    byte[] rb = resp.getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                    exchange.sendResponseHeaders(500, rb.length);
                    exchange.getResponseBody().write(rb);
                    exchange.getResponseBody().close();
                } catch (IOException ignore) {}
            }
        }
    }

    
    private static Map<String, String> parseFormData(String data) throws UnsupportedEncodingException {
        Map<String, String> map = new HashMap<>();
        for (String pair : data.split("&")) {
            String[] parts = pair.split("=");
            if (parts.length == 2)
                map.put(parts[0], URLDecoder.decode(parts[1], "UTF-8"));
        }
        return map;
    }
}


class StaticFileHandler implements HttpHandler {
    private final String baseDir;

    public StaticFileHandler(String baseDir) {
        this.baseDir = baseDir;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        if (path.equals("/")) path = "/login.html";

        String rel = path.startsWith("/") ? path.substring(1) : path;
        Path filePath = Paths.get(baseDir, rel).toAbsolutePath().normalize();
        File file = filePath.toFile().getCanonicalFile();
        if (!file.exists()) {
            String response = "404 Not Found";
            byte[] rb = response.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
            exchange.sendResponseHeaders(404, rb.length);
            exchange.getResponseBody().write(rb);
            exchange.getResponseBody().close();
            return;
        }

        String mime = Files.probeContentType(file.toPath());
        if (mime == null) mime = "application/octet-stream";
        exchange.getResponseHeaders().add("Content-Type", mime);

        byte[] bytes = Files.readAllBytes(file.toPath());
        exchange.sendResponseHeaders(200, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.getResponseBody().close();
    }
}


