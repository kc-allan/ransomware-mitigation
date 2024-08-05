from app import create_app, db
import flask
import os, subprocess

app = create_app(os.environ.get('FLASK_CONFIG') or 'default')


@app.after_request
def redirect_nextc(response):
    if flask.request.args.get('next'):
        return flask.redirect(flask.request.args.get('next'))
    return response


@app.shell_context_processor
def make_shell_context():
    """
    Context processor for the Flask shell.
    """
    return dict(db=db, app=app)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=True)
