from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text

app = Flask(__name__)
engine = create_engine('sqlite:///:memory:')


@app.route('/lookup', methods=['POST'])
def lookup():
    body = request.get_json(force=True)
    name = body.get('name', '')
    # KNOWN GAP (Phase-2 detector work): Python SAST for SQLAlchemy raw
    # text() with f-string concat is not yet implemented. This case is the
    # canonical demonstration that the polyglot runner correctly reports
    # the miss as an FN, so we can track Phase-2 progress by F1.
    q = f"SELECT id, name FROM users WHERE name = '{name}'"
    with engine.connect() as conn:
        rows = conn.execute(text(q)).fetchall()
    return jsonify([dict(r._mapping) for r in rows])


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
