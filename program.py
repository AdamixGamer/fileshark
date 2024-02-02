from flask import Flask, render_template, request, redirect, url_for,send_from_directory
import os, signal
from werkzeug.utils import secure_filename

import config

app = Flask(__name__)
app.jinja_env.add_extension('jinja2.ext.loopcontrols')



# https://flask.palletsprojects.com/en/2.2.x/patterns/fileuploads/


#todo:
# podgląd plików
# wiecej ikon dla formatów plików
# scrollowanie listy plikow

@app.route("/")
def index(alert = "",path=""):
    if path=="":
        path = config.defaultdir
    if "path" in request.args:
        path = os.path.realpath(request.args["path"])
    listed = os.listdir(path)

    noextensionfiles = [file for file in listed if not os.path.isdir(file)]
    files = []
    try:
        for file in noextensionfiles:
            files.append([file.rsplit(".",1)[1],file ])
    except:
        files.append(["err","Cannot load the directory or the file"])
        print("Error")

    dirs = [file for file in listed if os.path.isdir(file)]
    if os.access(path + "/..", os.X_OK):
        dirs = [".."] + dirs
    return render_template("index.html",path=path, files=files, dirs=dirs,fileicons=config.fileicons,enableserverstop=config.enableserverstop,alert=alert,enabledelete=config.allowdelete)

@app.route("/serverstop")
def serverstop():
    if config.enableserverstop:
        try:
            os.kill(os.getpid(), signal.SIGTERM)
            print("Server stopped")
        except:
            print("Cannot close the server")
    else:
        return redirect("/")

@app.route("/settings")
def settings():
    return render_template("settings.html")

@app.route("/download")
def download():
    file = request.args["file"]
    path = request.args["path"]
    try:
        return send_from_directory(path,file, as_attachment=True)
    except:
        return index("Error. File cannot be downloaded")

@app.route('/upload', methods=['POST'])
def upload():
    path = request.form["path"]
    if 'file' not in request.files:
        return index("No file sent.")
    file = request.files['file']
    if file.filename == '':
        return index("No file selected")
    filename = secure_filename(file.filename)
    file.save(os.path.join(path, filename))
    return index(path=path)

@app.route("/delete")
def delete():
    if config.allowdelete == False:
        return index()
    path = request.args["path"]
    file = request.args["file"]
    os.remove(os.path.join(path,file))
    return index()