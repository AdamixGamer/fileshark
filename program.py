from flask import Flask, render_template, request, redirect, url_for
import os, signal
from pathlib import Path

app = Flask(__name__)
app.jinja_env.add_extension('jinja2.ext.loopcontrols')

fileicons = ["bat","cpp","db","exe","iso","jar","jpg","md","png","py","rs","tiff","txt","html","unknown"]

#todo:
# plik konfiguracyjny
# podgląd plików
# pobieranie
# wgrywanie
#ikony zalezne od typu pliku

@app.route("/")
def index():
    path = '.'
    if "path" in request.args:
        path = os.path.realpath(request.args["path"])
    listed = os.listdir(path)

    noextensionfiles = [file for file in listed if not os.path.isdir(file)]
    files = []
    try:
        for file in noextensionfiles:
            files.append([file.rsplit(".",1)[1],file ])
    except:
        files.append(["err","Cannot load the directory"])
        print("error")

    dirs = [file for file in listed if os.path.isdir(file)]
    if os.access(path + "/..", os.X_OK):
        dirs = [".."] + dirs
    return render_template("index.html",path=path, files=files, dirs=dirs,fileicons=fileicons)

@app.route("/serverstop")
def serverstop():
    os.kill(os.getpid())
    print("Server stopped")