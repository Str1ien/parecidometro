from flask import Flask, render_template, jsonify

app = Flask(__name__)


@app.route("/")
def landing():
    return render_template("landing.html")


@app.route("/upload", methods=["POST"])
def upload_file():
    pass


@app.route("/visualize/<file_id>")
def visualize(file_id):
    return render_template("visualize.html", file_id=file_id)


@app.route("/api/file/<file_id>")
def api_file(file_id):

    # Placeholder for testing
    placeholder = {
        "SHA256": {
            "name": ["example.bin"],
            "size": "512 KB",
            "file_type": "binary",
            "upload_date": "2025-02-10 14:33:21",
            "desc": "Placeholder test file used for visualization",
            "hashes": {
                "sha256": "FAKEFAKEFAKE1234567890",
                "md5": "abcd1234abcd1234abcd1234abcd1234",
                "tlsh": "T12345ABCDEF098765",
                "ssdeep": "48:abcd1234efgh5678xyz/abcd1234:abcd1234ef"
            },

            "similar": [
                {
                    "name": "malware_sample_A.exe",
                    "tlsh_score": 83,
                    "ssdeep_score": 42
                },
                {
                    "name": "document_scan_v2.pdf",
                    "tlsh_score": 67,
                    "ssdeep_score": 5
                },
                {
                    "name": "archive_data_old.tar",
                    "tlsh_score": 55,
                    "ssdeep_score": 18
                },
                {
                    "name": "report_final.docx",
                    "tlsh_score": 44,
                    "ssdeep_score": 22
                },
                {
                    "name": "notes_backup.zip",
                    "tlsh_score": 38,
                    "ssdeep_score": 55
                }
            ]
        }
    }

    return jsonify(placeholder)


if __name__ == "__main__":
    app.run(debug=True)
