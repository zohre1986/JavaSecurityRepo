package servlets;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import java.io.IOException;
import java.sql.*;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@WebServlet("/pwd.do")
public class PwdServlet extends HttpServlet {
    private static final long serialVersionUID = -8123085861273087650L;
    public static final Pattern VALID_PASSWORD_REGEX = Pattern.compile("((?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!-/|:-@|\\[-`|{-~]).*)");

    private static DataSource ds;

    private Logger logger = Logger.getLogger(getClass().getName());

    static {
        try {
            InitialContext ctx = new InitialContext();
            //FIXED: OWASP A5:2017 - Broken Access Control (root privileges)
           // ds = (DataSource) ctx.lookup("jdbc/MySQL_root_DataSource");
            ds = (DataSource) ctx.lookup("jdbc/MySQL_Write_DataSource");
        } catch (NamingException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @Override
    protected void doGet(HttpServletRequest request,
                         HttpServletResponse response)
            throws IOException {

        logger.info("Received request from " + request.getRemoteAddr());

        try (Connection connection = ds.getConnection()) {

            Statement st = connection.createStatement();

            //FIXME: OWASP A2:2017 - Broken Authentication
            //  Username is determined based on client-provided information
            //  Session not checked
            String username = request.getParameter("username");

            //FIXME: OWASP A3:2017 - Sensitive Data Exposure
            // 1) URLs are often logged by web servers.
            //    Sensitive data such as passwords must not be included in URLs.
            //    Use POST method!
            // 2) Use TLS.
            String password = request.getParameter("password");
            String confirmPassword = request.getParameter("confirm");
            String oldPassword = request.getParameter("old");

            //FIXED: OWASP A5:2017 - Broken Access Control
            // Old password not checked

            String oldPassQry = "select password from users where username = ?";
            PreparedStatement preparedStatement = connection.prepareStatement(oldPassQry);
            preparedStatement.setString(1, username);
            ResultSet resultSet = preparedStatement.executeQuery();

            if(resultSet.first()){
                String oldPass = resultSet.getString("password");
                if (!oldPass.equals(oldPassword)) {
                    logger.warning("Your old password was incorrect!");
                    response.sendRedirect(response.encodeRedirectURL("/pages/failed.jsp"));
                    return;
                }
            }else {
                logger.warning("User NOT exist!");
                response.sendRedirect(response.encodeRedirectURL("/pages/failed.jsp"));
                return;
            }


            //FIXED: OWASP A5:2017 - Broken Access Control
            // Security policies not checked:

            //  2) minimum password age

            //  1) new password != old password
            if (password.equals(oldPassword)) {
                logger.warning("The old password must be different from new password!");
                response.sendRedirect(response.encodeRedirectURL("/pages/failed.jsp"));
                return;
            }

            if (!password.equals(confirmPassword)) {
                logger.warning("The new password must be equal to confirm password!");
                response.sendRedirect(response.encodeRedirectURL("/pages/failed.jsp"));
                return;
            }
            //  3) password complexity
            Matcher matcher = VALID_PASSWORD_REGEX.matcher(password);
            if (!matcher.find()) {
                logger.warning("The password complexity is violated");
                response.sendRedirect(response.encodeRedirectURL("/pages/failed.jsp"));
                return;
            }

            //  4) password length

            if (password == null || password.length() < 6) {
                logger.warning("The new password must be at least 6 character!");
                response.sendRedirect(response.encodeRedirectURL("/pages/failed.jsp"));
                return;
            }
            //FIXME: OWASP A1:2017 - Injection
            String query  = "Update users SET password = ? WHERE username = ?";
//               String.format("update users " +
//                            "set password = '%s' " +
//                            "where username = '%s'",
//                    password, username);
            PreparedStatement preparedStatement1 = connection.prepareStatement(query);

            //FIXME: OWASP A3:2017 - Sensitive Data Exposure
            // Log reveals sensitive info
            logger.info("Query: " + query);

            //FIXME: OWASP A10:2017 - Insufficient Logging & Monitoring
            // return value not logged
            //FIXME: OWASP A8:2013 - CSRF
//            st.executeUpdate(query);
            preparedStatement1.executeUpdate();
            //FIXED: OWASP A5:2017 - Broken Access Control
            //  Cookie used without any signature
            //FIXME: OWASP A3:2017 - Sensitive Data Exposure
            //  Password stored as plaintext on client-side
            //FIXME: OWASP A2:2017 - Broken Authentication
            //  Parameter "Remember me" is not observed
            //  Cookie security settings (httpOnly, secure, age, domain, path, same-site)
            //  For same-site, see: https://stackoverflow.com/a/43106260/459391
            //      response.setHeader("Set-Cookie", "key=value; HttpOnly; SameSite=strict")

//            Cookie pCookie = new Cookie("password", password);
//            response.addCookie(pCookie);

            response.sendRedirect("user.jsp");

        } catch (SQLException sqlException) {
            logger.warning(sqlException.getMessage());
        }
    }
}