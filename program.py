from flask import Flask, render_template, request, redirect, url_for,send_from_directory
import os, signal
import config

app = Flask(__name__)
app.jinja_env.add_extension('jinja2.ext.loopcontrols')






#todo:
# podgląd plików
# pobieranie (naprawic plik .txt)
# wgrywanie
# wiecej ikon dla formatów plików

@app.route("/")
def index():
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
        print("error")

    dirs = [file for file in listed if os.path.isdir(file)]
    if os.access(path + "/..", os.X_OK):
        dirs = [".."] + dirs
    return render_template("index.html",path=path, files=files, dirs=dirs,fileicons=config.fileicons,enableserverstop=config.enableserverstop)

@app.route("/serverstop")
def serverstop():
    if config.enableserverstop:
        print("Server stopped")
        os.kill(os.getpid(), signal.SIGTERM)
    else:
        return redirect("/")

@app.route("/settings")
def settings():
    return render_template("settings.html")

@app.route("/download")
def download():
    file = request.args["file"]
    path = request.args["path"]
    return send_from_directory(path,file)