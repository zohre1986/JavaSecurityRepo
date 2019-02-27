package filters;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

public class SessionManagerFilter implements Filter {

    private Logger logger = Logger.getLogger(getClass().getName());
    private String group;

    public void init(FilterConfig config) {
        group = config.getInitParameter("group");

        logger.info("Test Param: " + group);
    }

    @Override
    public void doFilter(ServletRequest request,
                         ServletResponse response,
                         FilterChain chain)
            throws IOException, ServletException {

        if (!(request instanceof HttpServletRequest &&
                response instanceof HttpServletResponse)) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        logger.info(String.format("Received request from IP address %s to URL %s.",
                request.getRemoteAddr(),
                ((HttpServletRequest) request).getServletPath()
        ));

        HttpSession session = req.getSession(false);

        if (session == null) {
            logger.info("No valid session found.");
            res.sendRedirect(String.format("%s/error.jsp?errno=1", req.getContextPath()));
            return;
        }

        @SuppressWarnings("unchecked")
        List<String> groups = (ArrayList<String>) session.getAttribute("groups");

        if (groups == null) {
            logger.warning("User not logged in");
            res.sendRedirect(String.format("%s/error.jsp?errno=2", req.getContextPath()));
            return;
        }

        if (!groups.contains(group)) {
            logger.warning(String.format(
                    "User does not belong to %s group", group
            ));
            res.sendRedirect(String.format("%s/error.jsp?errno=3", req.getContextPath()));
            return;
        }

        chain.doFilter(req, res);
    }
}
