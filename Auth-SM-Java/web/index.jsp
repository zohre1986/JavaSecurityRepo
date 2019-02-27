<%@ page import="org.jasypt.salt.RandomSaltGenerator" %>
<%@ page import="org.jasypt.commons.CommonUtils" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<c:set var="groups" value="${sessionScope['groups']}" scope="page"/>

<c:if test="${groups != null}">
    <c:choose>
        <c:when test="${groups.contains('admins')}">
            <c:redirect url="${pageContext.request.contextPath}/admins/"/>
        </c:when>
        <c:when test="${groups.contains('users')}">
            <c:redirect url="${pageContext.request.contextPath}/users/"/>
        </c:when>
        <c:when test="${groups.contains('guests')}">
            <c:redirect url="${pageContext.request.contextPath}/guests.html"/>
        </c:when>
        <c:otherwise>
            <%
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "You are group-less!");
            %>
        </c:otherwise>
    </c:choose>
</c:if>

<html>
<head>
    <title>Login</title>
    <jsp:include page="${pageContext.request.contextPath}/common.jsp"/>
</head>
<body>

<%--
    FIXME: This implementation is possibly broken due to concurrency issues
        See: "Are all stateful Web applications broken?"
        https://www.ibm.com/developerworks/library/j-jtp09238/index.html
--%>
<%
    if (session.getAttribute("csrf") == null) {
        RandomSaltGenerator rsg = new RandomSaltGenerator();
        String csrf = CommonUtils.toHexadecimal(rsg.generateSalt(16));
        session.setAttribute("csrf", csrf);
    }
%>

<div class="container">
    <h1>Login</h1>

    <hr>

    <form action="${pageContext.request.contextPath}/login.do" method="POST">

        <INPUT type="HIDDEN" name="csrf" value="${sessionScope["csrf"]}">

        <div class="form-group">
            <label for="username">Username:</label>
            <input class="form-control"
                   name="username" id="username"
                   placeholder="Enter username">
        </div>

        <div class="form-group">
            <label for="password">Password:</label>
            <input class="form-control" type="password"
                   name="password" id="password"
                   placeholder="Enter password">
        </div>

        <button type="submit" class="btn btn-primary btn-lg">Submit</button>
    </form>
</div>

</body>
</html>
