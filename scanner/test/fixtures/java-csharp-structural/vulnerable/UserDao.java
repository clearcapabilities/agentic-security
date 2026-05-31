import java.sql.*;
public class UserDao {
  public ResultSet find(Connection c, String name) throws Exception {
    return c.createStatement().executeQuery("SELECT * FROM users WHERE name='" + name + "'");
  }
}
