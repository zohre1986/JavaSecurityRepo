package servlets;

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

        HttpSession session = request.getSession();
        logger.info("Received request from " + request.getRemoteAddr());

        try (Connection connection = ds.getConnection()) {

            Statement st = connection.createStatement();

            //FIXME: OWASP A2:2017 - Broken Authentication
            //  Username is determined based on client-provided information
            //  Session not checked
            //String username = request.getParameter("username");
            String username = (String) session.getAttribute("username");

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

            if (resultSet.first()) {
                String oldPass = resultSet.getString("password");
                if (!oldPass.equals(oldPassword)) {
                    logger.warning("Your old password was incorrect!");
                    response.sendError(HttpServletResponse.SC_NOT_ACCEPTABLE,
                            "Your old password was incorrect!");
                    return;
                }
            } else {
                logger.warning("User NOT exist!");
                session.setAttribute("err" , "User NOT exist!");
                return;
            }


            //FIXED: OWASP A5:2017 - Broken Access Control
            // Security policies not checked:

            //  2) minimum password age

            //  4) password length

            if (password == null || confirmPassword == null || password.length() < 8) {
                logger.warning("The new password must be at least 8 character!");
                response.sendError(HttpServletResponse.SC_NOT_ACCEPTABLE,
                        "The new password must be at least 8 character!");
                return;
            }

            //  1) new password != old password
            if (password.equals(oldPassword)) {
                logger.warning("The old password must be different from new password!");
                response.sendError(HttpServletResponse.SC_NOT_ACCEPTABLE,
                        "The old password must be different from new password!");
                return;
            }

            if (!password.equals(confirmPassword)) {
                logger.warning("The new password must be equal to confirm password!");
                response.sendError(HttpServletResponse.SC_NOT_ACCEPTABLE,
                        "The new password must be equal to confirm password!");
                return;
            }
            //  3) password complexity
            Matcher matcher = VALID_PASSWORD_REGEX.matcher(password);
            if (!matcher.find()) {
                logger.warning("The password complexity is violated");
                response.sendError(HttpServletResponse.SC_NOT_ACCEPTABLE,
                        "The password complexity is violated");
                return;
            }


            //FIXME: OWASP A1:2017 - Injection
           /* String query = String.format("update users " +
                            "set password = '%s' " +
                            "where username = '%s'",
                    password, username);*/

            String query = "Update users SET password = ? WHERE username = ?";
            PreparedStatement preparedStatement1 = connection.prepareStatement(query);
            preparedStatement1.setString(1, password);
            preparedStatement1.setString(2, username);
//               String.format("update users " +
//                            "set password = '%s' " +
//                            "where username = '%s'",
//                    password, username);

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