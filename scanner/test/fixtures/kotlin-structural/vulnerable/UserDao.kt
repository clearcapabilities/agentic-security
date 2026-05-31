import java.sql.Connection
class UserDao(private val conn: Connection) {
  fun find(name: String): String {
    val rs = conn.createStatement().executeQuery("SELECT * FROM users WHERE name='${name}'")
    rs.next(); return rs.getString(1)
  }
}
