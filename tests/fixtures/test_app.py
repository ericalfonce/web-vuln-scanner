"""Integration test fixtures — minimal Flask app with login + vulnerable endpoints for testing."""
from flask import Flask, request, render_template_string, session, redirect, url_for

# Minimal test app with login and vulnerable endpoints
test_app_template = """
<html>
<head><title>Test App</title></head>
<body>
    {% if username %}
        <h1>Welcome {{ username }}!</h1>
        <p>You are logged in.</p>
        <form method="POST" action="/update">
            <input type="text" name="data" placeholder="data">
            <!-- Missing CSRF token -->
            <button type="submit">Update</button>
        </form>
        <script>
            var userInput = "{{ user_content | safe }}";
            document.body.innerHTML = userInput;
        </script>
    {% else %}
        <form method="POST" action="/login">
            <input type="text" name="username" required>
            <input type="password" name="password" required>
            <button type="submit">Login</button>
        </form>
    {% endif %}
</body>
</html>
"""


def create_test_app():
    """Create a minimal test Flask app with login and vulnerabilities."""
    app = Flask(__name__)
    app.secret_key = "test-secret"

    @app.route("/", methods=["GET"])
    def index():
        username = session.get("username")
        return render_template_string(test_app_template, username=username, user_content="")

    @app.route("/login", methods=["POST"])
    def login():
        username = request.form.get("username", "testuser")
        password = request.form.get("password", "")
        # Accept any credentials for testing
        session["username"] = username
        return redirect("/")

    @app.route("/update", methods=["POST"])
    def update():
        # Vulnerable endpoint (CSRF + data injection)
        return f"Data updated: {request.form.get('data', '')}"

    return app


if __name__ == "__main__":
    app = create_test_app()
    app.run(debug=True, port=5001)
