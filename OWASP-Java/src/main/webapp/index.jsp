<%@ page import="org.jasypt.salt.RandomSaltGenerator" %>
<%@ page import="org.jasypt.commons.CommonUtils" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<html>
<head>
    <title>Login</title>
    <jsp:include page="secure/common.jsp"/>
</head>
<body>
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

    <%--FIXME: OWASP A2:2017 - Broken Authentication
        Redirect user if he has already logged in
    --%>

    <%--FIXME: OWASP A3:2017 - Sensitive Data Exposure
        1) URLs are often logged by web servers.
           Sensitive data such as passwords must not be included in URLs.
           Use POST method!
        2) Use TLS.
    --%>
    <form action="login.do" method="post">

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

        <div class="checkbox">
            <label><input type="checkbox" name="remember"> Remember me</label>
        </div>

        <button type="submit" class="btn btn-primary btn-lg">Submit</button>
    </form>
</div>

</body>
</html>