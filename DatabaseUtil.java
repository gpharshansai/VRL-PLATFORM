import java.sql.*;
import java.util.*;

public class DatabaseUtil {
    private static final String URL = "jdbc:mysql://localhost:3306/vrl_platform?useSSL=false&serverTimezone=UTC";
    private static final String USER = "root";
    private static final String PASSWORD = "root"; 
    private static final String TABLE = "users";

    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            System.err.println("MySQL JDBC driver not found. Add the MySQL Connector/J JAR to the classpath.");
            e.printStackTrace();
        }
    }

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(URL, USER, PASSWORD);
    }

    public static void printConfig() {
        System.out.println("Database URL: " + URL);
        System.out.println("Database User: " + USER);
        System.out.println("Database Table: " + TABLE);
    }

    
    public static boolean saveRegistration(Map<String, String> data) throws SQLException {
       
        java.util.Map<String, String> colMap = new java.util.LinkedHashMap<>();

       
        String first = data.getOrDefault("firstName", "").trim();
        String last = data.getOrDefault("lastName", "").trim();
        String fullName = null;
        if (!first.isEmpty() || !last.isEmpty()) {
            fullName = (first + " " + last).trim();
            colMap.put("name", fullName);
        }

        if (data.containsKey("parentMobile") && data.get("parentMobile") != null && !data.get("parentMobile").isEmpty()) {
            colMap.put("phone", data.get("parentMobile"));
        }

        if (data.containsKey("age")) colMap.put("age", data.get("age"));
        if (data.containsKey("email")) colMap.put("email", data.get("email"));
        if (data.containsKey("password")) colMap.put("password", data.get("password"));
        
        if (data.containsKey("role")) colMap.put("role", data.get("role"));

        if (colMap.isEmpty()) return false;

        StringBuilder cols = new StringBuilder();
        StringBuilder placeholders = new StringBuilder();
        for (String col : colMap.keySet()) {
            if (cols.length() > 0) { cols.append(", "); placeholders.append(", "); }
            cols.append(col);
            placeholders.append("?");
        }

        String sql = "INSERT INTO " + TABLE + " (" + cols + ") VALUES (" + placeholders + ")";
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            int i = 1;
            for (Map.Entry<String, String> e : colMap.entrySet()) {
                String col = e.getKey();
                String val = e.getValue();
                
                if ("age".equals(col) && val != null && val.matches("\\d+")) {
                    ps.setInt(i++, Integer.parseInt(val));
                } else {
                    ps.setString(i++, val);
                }
            }
            int updated = ps.executeUpdate();
            return updated > 0;
        }
    }

    
    public static boolean validateLogin(String email, String password) {
        String sql = "SELECT * FROM users WHERE email = ? AND password = ?";
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, email);
            ps.setString(2, password);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            System.err.println("Login validation failed: " + e.getMessage());
            return false;
        }
    }

   
    public static boolean updateUserField(String email, String field, String newValue) {
      
        List<String> allowed = Arrays.asList("name", "phone", "age", "password", "role");
        if (!allowed.contains(field)) {
            System.err.println("Invalid field: " + field);
            return false;
        }

        String sql = "UPDATE users SET " + field + " = ? WHERE email = ?";
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, newValue);
            ps.setString(2, email);
            int updated = ps.executeUpdate();
            return updated > 0;
        } catch (SQLException e) {
            System.err.println("Failed to update user field: " + e.getMessage());
            return false;
        }
    }

    
    public static boolean updatePassword(String email, String newPassword) {
        return updateUserField(email, "password", newPassword);
    }

  
    public static boolean canConnect() {
        try (Connection c = getConnection()) {
            return c != null && !c.isClosed();
        } catch (SQLException e) {
            return false;
        }
    }

   
    public static String getUserRole(String email) {
        String sql = "SELECT role FROM users WHERE email = ?";
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, email);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    String r = rs.getString("role");
                    if (r == null || r.trim().isEmpty()) return "student";
                    return r.trim();
                }
            }
        } catch (SQLException e) {
            System.err.println("Failed to fetch user role: " + e.getMessage());
        }
        return "student";
    }

    public static boolean saveVideoMetadata(String filename, String title, String course, String chapter, String uploaderEmail) {
        return saveVideoMetadata(filename, title, course, chapter, null, null, uploaderEmail);
    }

    
    public static boolean saveVideoMetadata(String filename, String title, String course, String chapter, String session, String mode, String uploaderEmail) {
        String sql = "INSERT INTO videos (filename, title, course, chapter, session, mode, uploader_email) VALUES (?, ?, ?, ?, ?, ?, ?)";
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            ps.setString(1, filename);
            ps.setString(2, title);
            ps.setString(3, course);
            ps.setString(4, chapter);
            if (session == null || session.isEmpty()) {
                ps.setNull(5, Types.INTEGER);
            } else {
                try {
                    ps.setInt(5, Integer.parseInt(session));
                } catch (NumberFormatException nfe) {
                    ps.setNull(5, Types.INTEGER);
                }
            }
            ps.setString(6, mode == null ? "normal" : mode);
            ps.setString(7, uploaderEmail);
            int updated = ps.executeUpdate();
            if (updated > 0) {
                try (ResultSet keys = ps.getGeneratedKeys()) {
                    if (keys != null && keys.next()) {
                        long id = keys.getLong(1);
                        System.out.println("[DatabaseUtil] Inserted video metadata id=" + id + " filename=" + filename + " title=" + title + " session=" + session + " mode=" + mode);
                    }
                } catch (SQLException e) {
                    
                }
            }
            return updated > 0;
        } catch (SQLException e) {
            System.err.println("Failed to save video metadata: " + e.getMessage());
            return false;
        }
    }

    public static String getAllVideosJson() {
        String sql = "SELECT id, filename, title, course, chapter, session, mode, uploader_email, created_at FROM videos ORDER BY created_at DESC";
        StringBuilder sb = new StringBuilder();
        sb.append('[');
        boolean first = true;
        try (Connection conn = getConnection(); PreparedStatement ps = conn.prepareStatement(sql); ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                if (!first) sb.append(',');
                first = false;
                String filename = rs.getString("filename");
                String title = rs.getString("title");
                String course = rs.getString("course");
                String chapter = rs.getString("chapter");
                int session = rs.getInt("session");
                if (rs.wasNull()) session = -1;
                String mode = rs.getString("mode");
                String uploader = rs.getString("uploader_email");
                Timestamp created = rs.getTimestamp("created_at");
                String url = filename;
                try {
                    java.nio.file.Path p = java.nio.file.Paths.get(filename);
                    url = "/uploads/videos/" + p.getFileName().toString();
                } catch (Exception e) {
                   
                    if (filename != null) {
                        int idx = Math.max(filename.lastIndexOf('/'), filename.lastIndexOf('\\'));
                        if (idx >= 0 && idx + 1 < filename.length()) url = "/uploads/videos/" + filename.substring(idx + 1);
                    }
                }

                sb.append('{');
                sb.append("\"id\":").append(rs.getLong("id")).append(',');
                sb.append("\"filename\":\"").append(escapeJson(filename)).append("\",");
                sb.append("\"url\":\"").append(escapeJson(url)).append("\",");
                sb.append("\"title\":\"").append(escapeJson(title)).append("\",");
                sb.append("\"course\":\"").append(escapeJson(course)).append("\",");
                sb.append("\"chapter\":\"").append(escapeJson(chapter)).append("\",");
                sb.append("\"session\":").append(session).append(',');
                sb.append("\"mode\":\"").append(escapeJson(mode)).append("\",");
                sb.append("\"uploader\":\"").append(escapeJson(uploader)).append("\",");
                sb.append("\"created_at\":\"").append(created == null ? "" : created.toString()).append("\"");
                sb.append('}');
            }
        } catch (SQLException e) {
            System.err.println("Failed to fetch videos: " + e.getMessage());
        }
        sb.append(']');
        return sb.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }
}
