<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<%
    if (session == null)
        return;

    session.invalidate();

    for (Cookie c : request.getCookies()) {
        c.setMaxAge(0);
        c.setValue(null);
        response.addCookie(c);
    }
%>

<jsp:forward page="index.jsp"/>