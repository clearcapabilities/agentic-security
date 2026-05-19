from flask import Flask, request, send_file
from sqlalchemy import create_engine, text
import os
import subprocess
import pickle
import yaml

app = Flask(__name__)
engine = create_engine('sqlite:///:memory:')


@app.route('/sql', methods=['POST'])
def sql():
    name = request.json['name']
    # VULNERABLE: f-string SQL assigned to var, then passed to text()
    q = f"SELECT * FROM users WHERE name = '{name}'"
    with engine.connect() as conn:
        return [dict(r._mapping) for r in conn.execute(text(q))]


@app.route('/cmd', methods=['POST'])
def cmd():
    host = request.json['host']
    # VULNERABLE: os.system with user-controlled var
    os.system('ping -c 1 ' + host)
    # VULNERABLE: subprocess shell=True
    subprocess.run(f'nslookup {host}', shell=True)
    return 'ok'


@app.route('/pickle', methods=['POST'])
def pickle_load():
    # VULNERABLE: pickle.loads on request data
    return str(pickle.loads(request.data))


@app.route('/yaml', methods=['POST'])
def yaml_load():
    # VULNERABLE: yaml.load (no SafeLoader)
    return str(yaml.load(request.data))


@app.route('/eval', methods=['POST'])
def evil_eval():
    # VULNERABLE: eval on request data
    return str(eval(request.json['expr']))


@app.route('/file')
def file_download():
    # VULNERABLE: flask.send_file with user-controlled path
    return send_file(request.args.get('path'))


@app.route('/ssrf', methods=['POST'])
def ssrf():
    import requests
    # VULNERABLE: requests with user-controlled URL, verify=False
    return requests.get(request.json['url'], verify=False).text
