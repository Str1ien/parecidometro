from flask import Flask, render_template

app = Flask(__name__)


@app.route("/")
def landing():
    return render_template("landing.html")


@app.route("/upload", methods=["POST"])
def upload_file():
    pass


@app.route("/visualize/<file_sha256>")
def visualize(file_sha256):
    return render_template("visualize.html", file_sha256=file_sha256)


@app.route("/api/file/<file_sha256>")
def api_file(file_sha256):
    pass


if __name__ == "__main__":
    app.run(debug=True)
