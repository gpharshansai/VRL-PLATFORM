import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DatabaseUtil {
    // JDBC URL, username, and password for MySQL
    private static final String URL = "jdbc:mysql://localhost:3306/vrl_platform"; 
    private static final String USER = "root";
    private static final String PASSWORD = "7410"; 

    static {
        try {
            
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(URL, USER, PASSWORD);
    }
}
