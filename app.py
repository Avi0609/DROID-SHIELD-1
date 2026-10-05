from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
from analyzer import analyze_apk
import os

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    if "apk" not in request.files:
        return jsonify({"error": "No APK uploaded"}), 400

    f = request.files["apk"]
    if not f.filename.lower().endswith(".apk"):
        return jsonify({"error": "Please upload a valid .apk file"}), 400

    filename = secure_filename(f.filename)
    path = os.path.join(UPLOAD_DIR, filename)
    f.save(path)

    try:
        result = analyze_apk(path)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500
    finally:
        try:
            os.remove(path)
        except OSError:
            pass

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
