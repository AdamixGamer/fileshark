from flask import Flask, render_template, request, redirect, url_for,send_from_directory
import os, signal
from werkzeug.utils import secure_filename
import sqlite3
import bcrypt

import config

app = Flask(__name__)
app.jinja_env.add_extension('jinja2.ext.loopcontrols')


# https://flask.palletsprojects.com/en/2.2.x/patterns/fileuploads/



#todo:
# podgląd plików
# wiecej ikon dla formatów plików
# scrollowanie listy plikow
# dodac dzialajace ustawienia
#jezeli folder jest w folderze ktory nie jest . (/workspace/fileshark), program nie wykrywa folderów


logged = False
@app.route("/")
def index(alert = "",path=""):
    print(path)
    global logged
    if logged: #not logged
        return render_template("login.html",alert="Please login to access the website")
    if path=="":
        path = config.defaultdir
    if "path" in request.args:
        path = os.path.realpath(request.args["path"])
    listed = os.listdir(path)

    noextensionfiles = [file for file in listed if not os.path.isdir(file)]
    files = []
    for file in noextensionfiles:
        try:
            print(file)
            files.append([file.rsplit(".",1)[1], file])
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
    asattachment = request.args["attachment"]
    print(asattachment)
    try:
        return send_from_directory(path,file, as_attachment=asattachment)
    except:
        return index("Error. File cannot be downloaded or opened")

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

@app.route("/login", methods=['POST'])
def login(alert=""):
    username = request.form["login"]
    password = request.form["password"]
    hashes = sqlite3.connect("db/hashes.db")
    command = "select * from hashes where hashes.username = '" + username + "'"
    hashed = hashes.execute(command).fetchall()
    if len(hashed) == 0:
        return render_template("login.html",alert="Username or password is not correct. Please try again")

    if bcrypt.checkpw(password.encode('utf-8'), hashed[0][1].encode('utf-8')):
        global logged
        logged = True
        print("logged")
        return index()

    return render_template("login.html", alert="Username or password is not correct. Please try again")
    

def databasecreation():
    hashes = sqlite3.connect("db/hashes.db")

    hashes.execute("create table if not exists hashes(username text, hash text)")

    hash = bcrypt.hashpw(b"test", bcrypt.gensalt()).decode()
    print(hash)
    command = "insert into hashes(username,hash) values('test','" + hash + "')"
    hashes.execute(command)
    hashes.commit()

    hashes.close()