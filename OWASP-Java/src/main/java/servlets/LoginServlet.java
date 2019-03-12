package servlets;

import org.jasypt.util.password.StrongPasswordEncryptor;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;
import javax.sql.DataSource;
import java.io.IOException;
import java.sql.*;
import java.util.logging.Logger;
import java.util.regex.Pattern;

@WebServlet("/login.do")
public class LoginServlet extends HttpServlet {
    private static final long serialVersionUID = -1813590570829849128L;
    private static DataSource ds;
    private static Pattern usernamePattern = Pattern.compile("^[A-Za-z0-9_.]+$");
    private Logger logger = Logger.getLogger(getClass().getName());

    static {
        try {
            InitialContext ctx = new InitialContext();
            ds = (DataSource) ctx.lookup("jdbc/MySQL_readonly_DataSource");
        } catch (NamingException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @Override
    protected void doPost(HttpServletRequest request,
                         HttpServletResponse response)
            throws IOException {

        HttpSession session = request.getSession(false);



        if (session.getAttribute("userId") != null) {
            logger.warning("User already logged in...");
            response.sendRedirect(String.format("%s/error.jsp?errno=4", request.getContextPath()));
            return;
        }

        String userParam = request.getParameter("username");
        String passParam = request.getParameter("password");

        //FIXME: OWASP A7:2017 - Cross-Site Scripting (XSS)
        // Category: Reflected XSS (AKA Non-Persistent or Type II)
        // Category: Server XSS

        // Resolution 1: Use Content-Security-Policy (CSP)
        // Resolution 2: Sanitize input (as always!)
        if (userParam == null || passParam == null) {
            logger.warning("Either username or password is not provided.");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "Either username or password is not provided.");
            return;
        }
            // response.setContentType("text/html; charset=UTF-8");

            // NOTE: Internet Explorer, Chrome and Safari have a builtin "XSS filter" to prevent this.
            // Unless "X-XSS-Protection" is disabled, as shown below:

            // response.setHeader("X-XSS-Protection", "0");

            // Firefox, however, does not prevent reflected XSS.
            // See "Firefox - X-XSS-Protection Support.txt" for more info!

//            response.getWriter().printf("Either username or password is not provided.\n" +
//                            "Please check your input:\n" +
//                            "Username = %s\n" +
//                            "Password = %s",
//                    userParam, passParam);



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

        //FIXED: OWASP A1:2017 - Injection
        //FIXED: Use "LIMIT 1" at the end of query to improve performance
      /*  String query = String.format("select * from users " +
                        "where username = '%s' " +
                        "and password = '%s'",
                userParam, passParam);*/


        //FIXED: OWASP A3:2017 - Sensitive Data Exposure
        // logger.info("Query: " + query);

        String username, jasypt_pass, role;

        try (Connection connection = ds.getConnection()) {

            String selectSQL = "SELECT * FROM USERS WHERE USERNAME=? LIMIT 1";
            PreparedStatement preparedStatement = connection.prepareStatement(selectSQL);
            preparedStatement.setString(1, userParam);
            ResultSet rs = preparedStatement.executeQuery();

            logger.info("Query: " + preparedStatement.toString());

            if (!rs.next()) {
                logger.warning("User not found!");

                response.sendRedirect(response.encodeRedirectURL("failed.jsp"));
                return;
            }
            jasypt_pass = rs.getString("password");
            StrongPasswordEncryptor passwordEncryptor = new StrongPasswordEncryptor();

            if (!passwordEncryptor.checkPassword(passParam, jasypt_pass)) {
                logger.warning(String.format("userName or password is incorrect",
                        userParam));

                response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                        "userName or password is incorrect");
                return;
            }

            username = rs.getString("username");
            role = rs.getString("role");

            logger.info("User found.");

        } catch (SQLException sqlException) {
            logger.warning(sqlException.getMessage());
            response.sendRedirect("failed.jsp");
            return;
        }

        //FIXME: OWASP A2:2017 - Broken Authentication
        //  Parameter "Remember me" is not observed
        //  Cookie security settings (httpOnly, secure, age, domain, path, same-site)
        //  For same-site, see: https://stackoverflow.com/a/43106260/459391
        response.setHeader("Set-Cookie", "key=value; HttpOnly; SameSite=strict");

        //FIXED: OWASP A5:2017 - Broken Access Control
        //  Cookie used without any signature
//        Cookie uCookie = new Cookie("username", username);
//        response.addCookie(uCookie);


        session.invalidate();
        session = request.getSession(true);

        session.setAttribute("username", username);
        //FIXED: OWASP A5:2017 - Broken Access Control
        //  Cookie used without any signature
        //FIXED: OWASP A3:2017 - Sensitive Data Exposure
        //  Password stored as plaintext on client-side
//        Cookie pCookie = new Cookie("password", password);
//        response.addCookie(pCookie);

        //FIXED: OWASP A5:2017 - Broken Access Control
        //  Cookie used without any signature
//        Cookie rCookie = new Cookie("role", role);
//        response.addCookie(rCookie);
        session.setAttribute("role", role);

        response.sendRedirect("form/secure/user.jsp");
    }
}