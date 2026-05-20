import java.sql.*;
public class UserDao {
  public ResultSet find(Connection c, String name) throws Exception {
    PreparedStatement p = c.prepareStatement("SELECT * FROM users WHERE name=?");
    p.setString(1, name);
    return p.executeQuery();
  }
}
