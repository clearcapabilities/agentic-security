from flask import Flask, request, send_from_directory, abort
from sqlalchemy import create_engine, text
import subprocess
import json
import yaml
import os.path

app = Flask(__name__)
engine = create_engine('sqlite:///:memory:')
ALLOWED_HOSTS = {'example.com', 'api.example.com'}


@app.route('/sql', methods=['POST'])
def sql():
    name = request.json['name']
    # SAFE: parameterized via bindparams
    with engine.connect() as conn:
        return [dict(r._mapping) for r in conn.execute(
            text("SELECT * FROM users WHERE name = :name"),
            {"name": name}
        )]


@app.route('/cmd', methods=['POST'])
def cmd():
    host = request.json['host']
    if host not in ALLOWED_HOSTS:
        abort(400)
    # SAFE: argv-form, no shell
    subprocess.run(['ping', '-c', '1', host], check=True)
    return 'ok'


@app.route('/json', methods=['POST'])
def json_load():
    # SAFE: json instead of pickle
    return str(json.loads(request.data))


@app.route('/yaml', methods=['POST'])
def yaml_safe():
    # SAFE: safe_load
    return str(yaml.safe_load(request.data))


@app.route('/file/<name>')
def file_download(name):
    # SAFE: send_from_directory with a directory base
    return send_from_directory('/srv/files', name)
