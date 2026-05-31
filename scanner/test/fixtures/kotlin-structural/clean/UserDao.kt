import java.sql.Connection
class UserDao(private val conn: Connection) {
  fun find(name: String): String {
    val p = conn.prepareStatement("SELECT * FROM users WHERE name = ?")
    p.setString(1, name)
    val rs = p.executeQuery(); rs.next(); return rs.getString(1)
  }
}
