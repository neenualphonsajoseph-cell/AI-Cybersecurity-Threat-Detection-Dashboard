from flask import Flask, render_template, request, redirect, session, Response

from database import (
    init_db,
    save_threat,
    get_threats,
    get_threat_by_id
)

from threat_detector import detect_threat

app = Flask(__name__)
app.secret_key = "cyber_ai_secret_key"

init_db()


# ---------------- LOGIN ---------------- #

@app.route("/login", methods=["GET", "POST"])
def login():

    error = None

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        if username == "admin" and password == "admin123":

            session["user"] = username

            return redirect("/")

        else:
            error = "Invalid Credentials"

    return render_template(
        "login.html",
        error=error
    )


# ---------------- DASHBOARD ---------------- #

@app.route("/")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    threats = get_threats()

    critical_alert = False

    for threat in threats:
        if threat[2] == "CRITICAL":
            critical_alert = True
            break

    total_threats = len(threats)

    high_risk = len([
        t for t in threats
        if t[2] in ["HIGH", "CRITICAL"]
    ])

    recent_threats = threats[:5]

    return render_template(
        "dashboard.html",
        total_threats=total_threats,
        high_risk=high_risk,
        recent_threats=recent_threats,
        critical_alert=critical_alert
    )


# ---------------- ANALYZE ---------------- #

@app.route("/analyze", methods=["GET", "POST"])
def analyze():

    result = None

    if request.method == "POST":

        log_text = request.form["log_text"]

        result = detect_threat(log_text)

        save_threat(result)

    return render_template(
        "analyze.html",
        result=result
    )


# ---------------- HISTORY ---------------- #

@app.route("/history")
def history():

    search = request.args.get("search", "")

    threats = get_threats()

    if search:

        threats = [
            t for t in threats
            if search.lower() in str(t).lower()
        ]

    return render_template(
        "history.html",
        threats=threats,
        search=search
    )


# ---------------- THREAT DETAILS ---------------- #

@app.route("/threat/<int:threat_id>")
def threat_details(threat_id):

    threat = get_threat_by_id(threat_id)

    return render_template(
        "threat_details.html",
        threat=threat
    )


# ---------------- ABOUT ---------------- #

@app.route("/about")
def about():

    return render_template("about.html")


# ---------------- ANALYTICS ---------------- #

@app.route("/analytics")
def analytics():

    threats = get_threats()

    total = len(threats)

    high = len([
        t for t in threats
        if t[2] == "HIGH"
    ])

    critical = len([
        t for t in threats
        if t[2] == "CRITICAL"
    ])

    low = len([
        t for t in threats
        if t[2] == "LOW"
    ])

    return render_template(
        "analytics.html",
        total=total,
        high=high,
        critical=critical,
        low=low
    )


# ---------------- DOWNLOAD REPORT ---------------- #

@app.route("/download_report")
def download_report():

    threats = get_threats()

    def generate():

        yield "Timestamp,Threat Level,Threat Type,Failed Attempts,IP Address\n"

        for threat in threats:

            yield (
                f"{threat[1]},"
                f"{threat[2]},"
                f"{threat[3]},"
                f"{threat[4]},"
                f"{threat[5]}\n"
            )

    return Response(
        generate(),
        mimetype="text/csv",
        headers={
            "Content-Disposition":
            "attachment; filename=threat_report.csv"
        }
    )


# ---------------- FILE UPLOAD ---------------- #

@app.route("/upload_log", methods=["POST"])
def upload_log():

    file = request.files["log_file"]

    if file:

        content = file.read().decode("utf-8")

        result = detect_threat(content)

        save_threat(result)

    return redirect("/history")


# ---------------- LOGOUT ---------------- #

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


# ---------------- RUN APP ---------------- #

if __name__ == "__main__":
    app.run(debug=True)