package servlets;

import org.jasypt.util.password.StrongPasswordEncryptor;

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
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Pattern;


@WebServlet("/login.do")
public class LoginServlet extends HttpServlet {
    private static final long serialVersionUID = -5634608834051858775L;
    private static DataSource ds;

    // Using precompiled regex speeds up subsequent queries
    // XXX: Be vary of "Regular expression Denial of Service" (ReDoS) attacks
    // See: https://www.owasp.org/index.php/Regular_expression_Denial_of_Service_-_ReDoS
    // See: https://www.owasp.org/index.php/OWASP_Validation_Regex_Repository
    private static Pattern usernamePattern = Pattern.compile("^[A-Za-z0-9_.]+$");

    //FIXME: This implementation is possibly broken due to concurrency issues
    // See: "Are all stateful Web applications broken?"
    // https://www.ibm.com/developerworks/library/j-jtp09238/index.html

    private Logger logger = Logger.getLogger(getClass().getName());

    static {
        try {
            InitialContext ctx = new InitialContext();
            ds = (DataSource) ctx.lookup("jdbc/MySQL_ID_STOREU_DataSource");
        } catch (NamingException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request,
                          HttpServletResponse response)
            throws IOException {

        logger.info("Received login request from " + request.getRemoteAddr());

        HttpSession session = request.getSession(false);
        String csrf = request.getParameter("csrf");

        if (session == null
                || csrf == null
                || csrf.length() != 32
                || !csrf.equals(session.getAttribute("csrf"))) {

            logger.info("CSRF detected!");
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "CSRF detected!");
            return;
        }

        session.removeAttribute("csrf");

        if (session.getAttribute("userId") != null) {
            logger.warning("User already logged in...");
            response.sendRedirect(String.format("%s/error.jsp?errno=4", request.getContextPath()));
            return;
        }

        String userParam = request.getParameter("username");
        String passParam = request.getParameter("password");

        if (userParam.length() > 50 || passParam.length() > 50) {
            logger.warning("Too long username or password.");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "Too long username or password.");
            return;
        }

        if (!usernamePattern.matcher(userParam).matches()) {
            logger.warning("Invalid characters in username.");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "Invalid characters in username.");
            return;
        }

        String jasypt_pass;
        int userId;
        List<String> groups = new ArrayList<>();

        try (Connection connection = ds.getConnection()) {

            // Prepared statements are NOT susceptible to SQL Injection
            PreparedStatement pstmt = connection.prepareStatement(
                    "select * from users where username = ? LIMIT 1");

            pstmt.setString(1, userParam);

            ResultSet rs = pstmt.executeQuery();

            if (!rs.next()) {
                logger.warning(String.format("User %s not found!", userParam));

                response.sendRedirect(String.format("%s/error.jsp?errno=0", request.getContextPath()));
                return;
            }

            jasypt_pass = rs.getString("JASYPT_PASS");
            StrongPasswordEncryptor passwordEncryptor = new StrongPasswordEncryptor();

            if (!passwordEncryptor.checkPassword(passParam, jasypt_pass)) {
                logger.warning(String.format("Attempted login by username %s with wrong password.",
                        userParam));

                // The error should NOT differ from the case where username is wrong,
                // to prevent "username harvesting"
                response.sendRedirect(String.format("%s/error.jsp?errno=0", request.getContextPath()));
                return;
            }

            if (rs.getBoolean("IS_LOCKED")) {
                logger.warning(String.format("User %s is locked", userParam));

                response.sendError(HttpServletResponse.SC_FORBIDDEN,
                        "Your account is locked!");
                return;
            }

            userId = rs.getInt("id");

            pstmt = connection.prepareStatement("select GROUPNAME from `groups` where USERID = ?");
            pstmt.setInt(1, userId);

            rs = pstmt.executeQuery();

            while (rs.next())
                groups.add(rs.getString("GROUPNAME"));

            pstmt = connection.prepareStatement(
                    "update users set LAST_LOGON = CURRENT_TIMESTAMP where id = ? LIMIT 1");
            pstmt.setInt(1, userId);
            pstmt.executeUpdate();

        } catch (SQLException sqlException) {
            logger.warning(sqlException.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Problem with database. Please try again later.");
            return;
        }

        // Very important!
        // Prevents "session fixation" attacks.
        session.invalidate();
        session = request.getSession(true);

        session.setAttribute("userId", userId);
        session.setAttribute("username", userParam);
        session.setAttribute("groups", groups);
        session.setAttribute("loginTime", Instant.now());

        if (groups.contains("admins"))
            response.sendRedirect(String.format("%s/admins/", request.getContextPath()));
        else if (groups.contains("users"))
            response.sendRedirect(String.format("%s/users/", request.getContextPath()));
        else if (groups.contains("guests"))
            response.sendRedirect(String.format("%s/guests.html", request.getContextPath()));
        else
            response.sendError(HttpServletResponse.SC_FORBIDDEN,
                    "You are group-less!");

    }
}