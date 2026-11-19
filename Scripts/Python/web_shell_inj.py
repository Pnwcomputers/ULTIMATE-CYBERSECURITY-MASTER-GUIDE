"""Safe local file-upload example. No command execution or template hooks."""
from pathlib import Path

from flask import Flask, abort, request, send_from_directory
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif"}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024


@app.get("/")
def index():
    return "Safe local upload demo. Only approved image extensions are accepted."


@app.post("/upload")
def upload():
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        abort(400, "Choose a file to upload.")

    filename = secure_filename(uploaded.filename)
    suffix = Path(filename).suffix.lower()
    if not filename or suffix not in ALLOWED_EXTENSIONS:
        abort(400, "Only JPG, PNG, and GIF filenames are accepted.")

    uploaded.save(UPLOAD_DIR / filename)
    return "Upload saved as an attachment-only file."


@app.get("/uploads/<path:filename>")
def downloads(filename):
    # Reject path components and serve uploads only as downloads.
    safe_name = secure_filename(filename)
    if not safe_name or safe_name != filename:
        abort(404)
    return send_from_directory(UPLOAD_DIR, safe_name, as_attachment=True)


if __name__ == "__main__":
    # Keep the development server on loopback; use a production server for deployment.
    app.run(host="127.0.0.1", port=5000, debug=False)
