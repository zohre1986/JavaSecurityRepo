package servlets;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.sql.DataSource;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Logger;

@WebServlet("/comment.do")
public class CommentServlet extends HttpServlet {
    private static final long serialVersionUID = -6689380769108812893L;
    private static DataSource ds;

    private Logger logger = Logger.getLogger(getClass().getName());

    static {
        try {
            InitialContext ctx = new InitialContext();
            //FIXED: OWASP A5:2017 - Broken Access Control (root privileges)
            //ds = (DataSource) ctx.lookup("jdbc/MySQL_root_DataSource");
            ds = (DataSource) ctx.lookup("jdbc/MySQL_Write_DataSource");
        } catch (NamingException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request,
                          HttpServletResponse response)
            throws IOException {

        logger.info("Received request from " + request.getRemoteAddr());

        //FIXED: OWASP A5:2017 - Broken Access Control
        HttpSession session = request.getSession();
        String username = session.getAttribute("username").toString();

        //String username = request.getParameter("username");

        String comment = request.getParameter("comment");

        //FIXED: OWASP A1:2017 - Injection
       /* String query = String.format("INSERT INTO guestbook (userId, comment) " +
                        "VALUES ((SELECT id FROM users WHERE username='%s'), '%s')",
                username, comment);*/
//        String query = String.format("INSERT INTO guestbook (userId, comment) " +
//                        "VALUES ((SELECT id FROM users WHERE username='%s'), '%s')",
//                username, comment);

        String query = String.format("INSERT INTO guestbook (userId, comment) " +
                "VALUES ((SELECT id FROM users WHERE username = ? LIMIT 1),?)");
        try (Connection connection = ds.getConnection()) {
            Statement st = connection.createStatement();
            PreparedStatement preparedStatement = connection.prepareStatement(query);
            preparedStatement.setString(1, username);
            preparedStatement.setString(2, comment);

            //FIXME: OWASP A10:2017 - Insufficient Logging & Monitoring
            // return value not logged
            //FIXME: OWASP A8:2013 - CSRF
            int result = preparedStatement.executeUpdate();
            logger.info(result + " row(s) affected by update query.");
            //FIXED: OWASP A8:2013 - CSRF
//            st.executeUpdate(query);

        } catch (SQLException sqlException) {
            logger.warning(sqlException.getMessage());

            response.sendRedirect("error.jsp");
            return;
        }

        response.sendRedirect("success.jsp");
    }
}