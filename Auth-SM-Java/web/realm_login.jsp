<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<html>
<head>
    <title>Login</title>
    <jsp:include page="common.jsp"/>
</head>
<body>

<div class="container">
    <h1>Login</h1>

    <hr>

    <form action="j_security_check" method="POST">

        <div class="form-group">
            <label for="j_username">Username:</label>
            <input class="form-control"
                   name="j_username" id="j_username"
                   placeholder="Enter username">
        </div>

        <div class="form-group">
            <label for="j_password">Password:</label>
            <input class="form-control" type="password"
                   name="j_password" id="j_password"
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
