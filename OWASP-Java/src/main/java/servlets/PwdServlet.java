package servlets;

import org.jasypt.util.password.StrongPasswordEncryptor;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;
import javax.sql.DataSource;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.io.PrintWriter;
import java.sql.*;
import java.time.LocalDate;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@WebServlet("/pwd.do")
public class PwdServlet extends HttpServlet {
    private static final long serialVersionUID = -8123085861273087650L;
    private static Pattern usernamePattern = Pattern.compile("^[A-Za-z0-9_.]+$");
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
    protected void doPost(HttpServletRequest request,
                         HttpServletResponse response)
            throws IOException {

        logger.info("Received request from " + request.getRemoteAddr());

        try (Connection connection = ds.getConnection()) {

            Statement st = connection.createStatement();

            //FIXED: OWASP A2:2017 - Broken Authentication
            //  Username is determined based on client-provided information
            //  Session not checked
            //String username = request.getParameter("username");
            HttpSession session = request.getSession(false);
            String username = (String) session.getAttribute("username");
            //added by hourieh
            if (!usernamePattern.matcher(username).matches()) {
                logger.warning("Invalid characters in username.");
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                        "Invalid characters in username.");
                return;
            }

            //FIXME: OWASP A3:2017 - Sensitive Data Exposure (FIXED)
            // 1) URLs are often logged by web servers.
            //    Sensitive data such as passwords must not be included in URLs.
            //    Use POST method!
            // 2) Use TLS.
            //do by hourieh
            String password = request.getParameter("password");
            String confirmPassword = request.getParameter("confirm");
           // String oldPassword = request.getParameter("old");


            //FIXED: OWASP A5:2017 - Broken Access Control
            // Old password not checked
            String oldPassword;
            String oldPassQry = "select password , updated_at from users where username = ?";
            PreparedStatement preparedStatement = connection.prepareStatement(oldPassQry);
            preparedStatement.setString(1, username);
            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.first()) {
                logger.info("User found.");
                 oldPassword = resultSet.getString("password");

                if (oldPassword.equals(request.getParameter("old"))) {
                    logger.warning("Your new password must be different from your previous password.!");
                    response.sendRedirect(response.encodeRedirectURL("/pages/failed.jsp"));
                    return;
                }
            } else {
                logger.warning("User NOT found!");
                response.sendRedirect(response.encodeRedirectURL("/pages/failed.jsp"));
                return;
            }



            //FIXED: OWASP A5:2017 - Broken Access Control
            // Security policies not checked:
            //  1) new password != old password
            //  2) minimum password age
            //  3) password complexity
            //  4) password length


            String dbPassword = resultSet.getString("password");
            StrongPasswordEncryptor passwordEncryptor = new StrongPasswordEncryptor();



            Date updatedDate = resultSet.getDate("updated_at");
            if (updatedDate.before(Date.valueOf(LocalDate.now()))) {
                logger.warning("you changed your password one time today");
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                        "you changed your password one time today!");
                return;
            }
            if (passwordEncryptor.checkPassword(oldPassword, dbPassword)) {
                logger.warning("Your old password was incorrect!");
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                        "Your old password was incorrect!");
                return;
            }



            if (password == null || confirmPassword == null || password.length() < 8) {
                logger.warning("The new password must be at least 8 character!");
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                        "The new password must be at least 8 character!");
                return;
            }

            if (password.equals(oldPassword)) {
                logger.warning("The old password must be different from new password!");
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                        "The old password must be different from new password!");
                return;
            }

            if (!password.equals(confirmPassword)) {
                logger.warning("The new password must be equal to confirm password!");
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                        "The new password must be equal to confirm password!");
                return;
            }

            Matcher matcher = VALID_PASSWORD_REGEX.matcher(password);
            if (!matcher.find()) {
                logger.warning("The password complexity is violated");
                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                        "The password complexity is violated");
                return;
            }


            //FIXED: OWASP A1:2017 - Injection
           /* String query = String.format("update users " +
                            "set password = '%s' " +
                            "where username = '%s'",
                    password, username);*/
            String encryptedPassword = passwordEncryptor.encryptPassword(password);

            String query = "Update users SET password = ? , updated_at = ? WHERE username = ?";
            PreparedStatement preparedStatement1 = connection.prepareStatement(query);
            preparedStatement1.setString(1, encryptedPassword);
            preparedStatement1.setDate(2, Date.valueOf(LocalDate.now()));
            preparedStatement1.setString(3, username);
//               String.format("update users " +
//                            "set password = '%s' " +
//                            "where username = '%s'",
//                    password, username);

            //FIXED: OWASP A3:2017 - Sensitive Data Exposure
            // Log reveals sensitive info
           // logger.info("Query: " + preparedStatement1.toString());

            //FIXED: OWASP A10:2017 - Insufficient Logging & Monitoring
            // return value not logged
            //FIXME: OWASP A8:2013 - CSRF
//            st.executeUpdate(query);
            preparedStatement1.executeUpdate();
            logger.info("user: " + username + " has changed password");
            //FIXED: OWASP A5:2017 - Broken Access Control
            //  Cookie used without any signature
            //FIXED: OWASP A3:2017 - Sensitive Data Exposure
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