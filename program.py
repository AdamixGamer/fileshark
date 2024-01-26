from flask import Flask, render_template, request, redirect, url_for
import os

app = Flask(__name__)
fileiconlist = ["py","txt","md"]
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
    
    files = [file for file in listed if not os.path.isdir(file)]
    dirs = [file for file in listed if os.path.isdir(file)]
    if os.access(path + "/..", os.X_OK):
        dirs = [".."] + dirs

    return render_template("index.html",path=path, files=files, dirs=dirs)