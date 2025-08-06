from flask import Flask, request
import uuid

app = Flask(__name__)


def log_request():
    headers = request.headers
    header_str = "\n".join([f"{key}: {value}" for key, value in headers.items()])
    req_id = str(uuid.uuid4())
    log_entry = f"ID: {req_id}\nPath: {request.path}\n{header_str}\n{'-'*40}\n"
    with open("requests.log", "a") as f:
        f.write(log_entry)

@app.before_request
def before_request_logging():
    log_request()

@app.route('/')
def index():
    return "HTTP/3 ON STEROIDS"

@app.route('/admin')
def admin():
    return "Hello, pepega Admin! This is a protected route. H3.X HTTP/3 ON STEROIDS/reborned!"

@app.route('/get')
def print_headers():
    header_str = "\n".join([f"{key}: {value}" for key, value in request.headers.items()])
    return header_str

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
