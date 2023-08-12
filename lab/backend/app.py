from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def print_headers():
    headers = request.headers
    header_str = "\n".join([f"{key}: {value}" for key, value in headers.items()])
    return header_str

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
