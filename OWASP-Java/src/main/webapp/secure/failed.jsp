<html>
<head>
    <title>Login Failed</title>
    <jsp:include page="form/secure/common.jsp"/>
</head>
<body>

<div class="container">
    <h1 style="color: red;">Invalid username or password!</h1>
    <h2>Try to <a href="../index.jsp?CSRF_NONCE=<%=response.encodeURL(null)%>">login</a> again.</h2>
</div>
</body>
</html>