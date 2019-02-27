<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<html>
<head>
    <title>Error</title>
    <jsp:include page="common.jsp"/>
</head>
<body>

<div class="container">
    <h1>Access denied!</h1>
    <hr>

    <div class="row">
        <div class="col-md-12" style="color: red;">
            <c:set var="errno" value="${param.errno}" scope="page"/>
            <c:choose>
                <c:when test="${errno == 0}">
                    Invalid username or password!
                    Try to <a href="${pageContext.request.contextPath}/index.jsp">login</a> again.
                </c:when>
                <c:when test="${errno == 1}">
                    Server session not found!
                    You must <a href="${pageContext.request.contextPath}/index.jsp">login</a> first!
                </c:when>
                <c:when test="${errno == 2}">
                    You must <a href="${pageContext.request.contextPath}/index.jsp">login</a> first!
                </c:when>
                <c:when test="${errno == 3}">
                    You are not authorized to see this page!
                    <a href="${pageContext.request.contextPath}/logout.jsp">Logout</a>,
                    and login with another username/password.
                </c:when>
                <c:when test="${errno == 4}">
                    You've already logged in! Why are you wasting our time?
                </c:when>
                <c:otherwise>
                    Unknown error!
                </c:otherwise>
            </c:choose>
        </div>
    </div>

    <div class="row">
        <div class="col-md-12">
            The site administrator was notified.
        </div>
    </div>

    <div class="row">
        <div class="col-md-12">
            <img src="${pageContext.request.contextPath}/static/img/error.jpg">
        </div>
    </div>
</div>
</body>
</html>