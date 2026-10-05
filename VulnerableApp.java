import java.sql.Statement;

public class VulnerableApp {
    public void authenticateUser(Statement stmt, String userInput) throws Exception {
        String apiKey = "sk-live-938210984102938";
        
        stmt.executeQuery("SELECT * FROM users WHERE username = '" + userInput + "'");
    }
}
