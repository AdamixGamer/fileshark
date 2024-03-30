from flask import Flask, render_template, request, redirect, url_for,send_from_directory
import os, signal
from werkzeug.utils import secure_filename
import sqlite3
import bcrypt
import uuid
import shutil

import config

app = Flask(__name__)
app.jinja_env.add_extension('jinja2.ext.loopcontrols')


#todo:
# podgląd plików
# wiecej ikon dla formatów plików
# dodac dzialajace ustawienia (po folderach domowych)
# dodac folder domowy
# dodac uzytkownika administratora


@app.route("/")
def index(alert = "", path="",sessionid=""):
    print(path)
    
    if sessionid=="": 
        if "sessionid" not in request.args:
            return render_template("login.html",alert="Please login to access the website")
        else:
            sessionid = request.args["sessionid"]
    if not checksession(sessionid):
            return render_template("login.html",alert="Session id does not exist, please login again")
    if path=="":
        with sqlite3.connect("db/hashes.db") as userfolder:
            username = userfolder.execute(f"select username from sessionid where sessionid=:sessionid",{"sessionid":sessionid}).fetchall()[0][0]
            path = config.defaultdir + "/" + username
    if "path" in request.args:
        path = os.path.realpath(request.args["path"])

    #if not checkpath(sessionid,path):
    #    return index(alert = "You are not allowed to access the directory", path=path,sessionid=sessionid)

    listed = os.listdir(path)

    noextensionfiles = [file for file in listed if not os.path.isdir(os.path.join(path, file))]
    files = []
    for file in noextensionfiles:
        try:
            files.append([file.rsplit(".",1)[1], file])
        except:
            files.append(["err","Cannot load the directory or the file"])
            print("Error")

    dirs = [file for file in listed if os.path.isdir(os.path.join(path, file))]
    if os.access(path + "/..", os.X_OK):
        dirs = [".."] + dirs
    return render_template("index.html",path=path, files=files, dirs=dirs, sessionid=sessionid,fileicons=config.fileicons,enableserverstop=config.enableserverstop,alert=alert,enabledelete=config.allowdelete)

@app.route("/serverstop")
def serverstop():
    if "sessionid" not in request.args:
        return render_template("login.html",alert="Please login to access the website")
    else:
        sessionid = request.args["sessionid"]
    if not checksession(sessionid):
            return render_template("login.html",alert="Session id does not exist, please login again")
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
    if "sessionid" not in request.args:
        return render_template("login.html",alert="Please login to access the website")
    else:
        sessionid = request.args["sessionid"]
    if not checksession(sessionid):
            return render_template("login.html",alert="Session id does not exist, please login again")
    return render_template("settings.html", sessionid=sessionid, alert="")


@app.route("/addfolder")
def addfolder():
    if "sessionid" not in request.args:
        return render_template("login.html",alert="Please login to access the website")
    else:
        sessionid = request.args["sessionid"]
    if not checksession(sessionid):
            return render_template("login.html",alert="Session id does not exist, please login again")
    path = request.args["path"]
    name = request.args["foldername"]
    fullpath = os.path.join(path, name)
    if os.path.exists(fullpath):
        if os.path.isdir(fullpath):
            return index(alert="This folder already exists!",path=path,sessionid=sessionid)
        else:
            return index(alert="File with the same name already exists!",path=path,sessionid=sessionid)
    else:
        try:
            os.mkdir(fullpath)
        except e:
            return index(alert=e.message,path=path,sessionid=sessionid)
        return index(path=path,sessionid=sessionid)

    
@app.route("/download")
def download():
    if "sessionid" not in request.args:
        return render_template("login.html",alert="Please login to access the website")
    else:
        sessionid = request.args["sessionid"]
    if not checksession(sessionid):
            return render_template("login.html",alert="Session id does not exist, please login again")
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
    if "sessionid" not in request.form:
        return render_template("login.html",alert="Please login to access the website")
    else:
        sessionid = request.form["sessionid"]
    if not checksession(sessionid):
            return render_template("login.html",alert="Session id does not exist, please login again")
    path = request.form["path"]
    if 'file' not in request.files:
        return index("No file sent.")
    file = request.files['file']
    if file.filename == '':
        return index("No file selected")
    filename = secure_filename(file.filename)
    file.save(os.path.join(path, filename))
    return index(path=path,sessionid=sessionid)


@app.route("/delete")
def delete():
    if "sessionid" not in request.args:
        return render_template("login.html",alert="Please login to access the website")
    else:
        sessionid = request.args["sessionid"]
    if not checksession(sessionid):
            return render_template("login.html",alert="Session id does not exist, please login again")
    if config.allowdelete == False:
        return index(sessionid=sessionid)
    path = request.args["path"]
    file = request.args["file"]
    os.remove(os.path.join(path,file))
    return index(sessionid=sessionid)

@app.route("/deletedir")
def deletedir():
    if "sessionid" not in request.args:
        return render_template("login.html",alert="Please login to access the website")
    else:
        sessionid = request.args["sessionid"]
    if not checksession(sessionid):
            return render_template("login.html",alert="Session id does not exist, please login again")
    if config.allowdelete == False:
        return index(sessionid=sessionid)
    path = request.args["path"]
    file = request.args["dir"]
    fullpath = os.path.join(path,file)
    if os.path.exists(fullpath):
        if os.path.isdir(fullpath):
            if len(os.listdir(fullpath)) > 0:
                if "allowdelete" not in request.args:
                    return render_template("deletefolder.html",sessionid=sessionid,path=path,dir=file,)
                else:
                    shutil.rmtree(fullpath)
                    return index(path=path,sessionid=sessionid)
            else:
                shutil.rmtree(fullpath)
                return index(path=path,sessionid=sessionid)
        else:
            return index(alert="Error",path=path,sessionid=sessionid)
    else:
        return index(alert="Folder does not exist",path=path,sessionid=sessionid)
    return index(alert="Cannot delete the folder",path=path,sessionid=sessionid)
    
    

@app.route("/login", methods=['POST'])
def login(alert=""):
    username = request.form["login"]
    password = request.form["password"]
    with sqlite3.connect("db/hashes.db") as hashes:
        hashes.execute("delete from sessionid where sessionlifetime < datetime('now')")
        hashed = hashes.execute("select * from hashes where hashes.username = :username",{"username":username}).fetchall()
        if len(hashed) == 0:
            return render_template("login.html",alert="Username or password is not correct. Please try again")
        if bcrypt.checkpw(password.encode('utf-8'), hashed[0][1].encode('utf-8')):
            sessionid = str(uuid.uuid4())
            hashes.execute(f"insert into sessionid values(:username,:sessionid,datetime('now', '+{config.SESSION_LIFETIME} minutes'))", {"username":username, "sessionid":sessionid})
            hashes.commit()
            print("logged")
            return index(sessionid=sessionid)
    return render_template("login.html", alert="Username or password is not correct. Please try again")


@app.route("/logout")
def logout():
    sessionid=request.args["sessionid"]
    with sqlite3.connect("db/hashes.db") as session:
        session.execute("DELETE FROM sessionid WHERE sessionid=:sessionid",{"sessionid":sessionid})
    return render_template("login.html",alert="")


@app.route("/loadusercreate") #not final
def loadusercreate():
    return render_template("createuser.html")


@app.route("/createuser", methods=['POST'])
def createuser():
    databasecreation()
    username = request.form["login"]
    password = request.form["password"]
    repeatpassword = request.form["repeatpassword"]
    #username checks
    
    if len(username) < 3:
        return render_template("createuser.html",alert="Username is too short. Minimal length is 3")
    if len(username) > 24:
        return render_template("createuser.html",alert="Username is too long. Maximum length is 24")

    #passwords checks
    if password != repeatpassword:
        return render_template("createuser.html",alert="Passwords do not match")
    if len(password) < 6:
        return render_template("createuser.html",alert="Password is too short. Minimal length is 6")
    if len(password) > 32:
        return render_template("createuser.html",alert="Username is too long. Maximum length is 32")

    with sqlite3.connect("db/hashes.db") as newuser:
        #database checks

        usernamecount = newuser.execute("select count(*) from hashes where username=:username", {"username":username}).fetchall()[0][0]
        if usernamecount > 0:
            return render_template("createuser.html",alert="Username or password is not correct")
        hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        newuser.execute("insert into hashes(username,hash) values(:username,:hash)",{"username":username,"hash":hash})
        os.mkdir(config.defaultdir + "/" + username)
        newuser.commit()

    return render_template("login.html",alert="Account was created, please login")


def databasecreation():
    hashes = sqlite3.connect("db/hashes.db")

    hashes.execute("create table if not exists hashes(username text UNIQUE, hash text)")
    hashes.execute("create table if not exists sessionid(username text , sessionid text, sessionlifetime datetime)")
    
    ##hash = bcrypt.hashpw(b"test", bcrypt.gensalt()).decode()
    ##print(hash)
    ##command = "insert into hashes(username,hash) values('test','" + hash + "')"
    ##hashes.execute(command)
    ##hashes.commit()

    hashes.close()


def checksession(sessionid):
    print(request.remote_addr)
    print("----")
    with sqlite3.connect("db/hashes.db") as checksession:
        result = checksession.execute("select * from sessionid where sessionid=:sessionid and sessionlifetime > datetime('now')",{"sessionid":sessionid}).fetchall()
        if len(result) == 0:
            return False
        checksession.execute(f"update sessionid set sessionlifetime=datetime('now', '+{config.SESSION_LIFETIME} minutes') where sessionid=:sessionid",{"sessionid":sessionid})
        checksession.commit()
    return True

def checkpath(sessionid,path):
    with sqlite3.connect("db/hashes.db") as checkpath:
        
        username = checkpath.execute(f"select username from sessionid where sessionid=:sessionid",{"sessionid":sessionid}).fetchall()[0][0]
        print(f"{path.split(username,1)[0] + "/" + username} |  {os.path.join(config.defaultdir,username)}")
        if path.split(username,1)[0] + "/" + username  != os.path.join(config.defaultdir,username):
            return False
    return True