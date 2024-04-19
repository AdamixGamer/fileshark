from flask import Flask, render_template, request, redirect, url_for,send_from_directory
import os, signal
from werkzeug.utils import secure_filename
import sqlite3
import bcrypt
import uuid
import shutil
import json
import logging

import config



def SetupLogger(name,filename="logs/serverlogs.log"):
    logger = logging.getLogger(name)

    handler = logging.FileHandler(filename)
    handler.setFormatter(logging.Formatter('%(levelname)s:%(name)s: %(message)s : Date: %(asctime)s'))
    logger.addHandler(handler)

    if filename != "logs/serverlogs.log":
        handler = logging.FileHandler("logs/serverlogs.log")
        handler.setFormatter(logging.Formatter('%(levelname)s:server:%(name)s: %(message)s : Date: %(asctime)s'))
        logger.addHandler(handler)
    
    logger.setLevel(logging.INFO)
    return logger

logging.basicConfig(filename='logs/global.log', level=logging.INFO)


app = Flask(__name__)
app.jinja_env.add_extension('jinja2.ext.loopcontrols')

# done:
# foldery uzytkownika (kopiowanie /userblueprint)
# config uzytkownika
# ustawienia uzytkownika
# permisje folderow uzytkownika
# administrator

# todo:
# podgląd plików
# wiecej ikon dla formatów plików
# edycja plików
# lepszy css
# light mode i dark mode ?

# https://www.w3schools.com/sql/sql_foreignkey.asp


@app.route("/")
def index(alert = "", path="",sessionid=""):
    printip()
    if sessionid=="": 
        if "sessionid" not in request.args:
            return render_template("login.html",alert="Please login to access the website")
        else:
            sessionid = request.args["sessionid"]
    if not checksession(sessionid):
            return render_template("login.html",alert="Session id does not exist, please login again")
    if path=="":
        path = config.defaultdir + "/" + GetUsername(sessionid)
    if "path" in request.args:
        path = os.path.realpath(request.args["path"])
    username = GetUsername(sessionid)
    checkadminperms = IsUserAdmin(sessionid)
    if not checkadminperms:
        if not checkpath(sessionid,path):
            alert = "You are not allowed to access the directory"
            path=config.defaultdir + "/" + username
            sessionid=sessionid
            userpath = getuserpath(path)
        else:
            userpath = getuserpath(path)
    else:
        userpath = path

    #print(userpath)
    listed = os.listdir(path)

    noextensionfiles = [file for file in listed if not os.path.isdir(os.path.join(path, file))]
    files = []
    for file in noextensionfiles:
        try:
            files.append([file.rsplit(".",1)[1], file])
        except:
            files.append(["err","Cannot load the directory or the file"])
            print("Error")

    dirs = [file for file in listed if os.path.isdir(os.path.join(path, file)) and (file !="systemfiles" or checkadminperms)]
    if os.access(path + "/..", os.X_OK):
        username = GetUsername(sessionid)
        if not checkadminperms:
            if path!=config.defaultdir + "/" + username:
                dirs = [".."] + dirs
        else:
            dirs = [".."] + dirs

    AddLog(action=f"Loaded directory : {path}",sessionid=sessionid,level="INFO")
    return render_template("index.html",path=path, files=files, dirs=dirs, sessionid=sessionid,\
    fileicons=config.fileicons,enableserverstop=config.enableserverstop,alert=alert,userpath=userpath,\
    enabledelete=LoadUserConfig(sessionid)["allowdelete"], adminperms = IsUserAdmin(sessionid))

@app.route("/serverstop")
def serverstop():
    if "sessionid" not in request.args:
        return render_template("login.html",alert="Please login to access the website")
    else:
        sessionid = request.args["sessionid"]
    if not checksession(sessionid):
            return render_template("login.html",alert="Session id does not exist, please login again")
    if config.enableserverstop and IsUserAdmin(sessionid):
        try:
            AddLog(action=f"Server stopped by {GetUsername(sessionid)}",level="INFO")
            AddLog(action=f"Server stopped",sessionid=sessionid,level="INFO")
            os.kill(os.getpid(), signal.SIGTERM)
        except:
            print("Cannot close the server")
            AddLog(action=f"Cannot close the server",sessionid=sessionid,level="ERROR")
            return index(alert="Error. Cannot stop the server",sessionid=sessionid)
    else:
        return index(alert="Server stop is disabled or you lack permission",sessionid=sessionid)


@app.route("/settings")
def settings(): 
    if "sessionid" not in request.args:
        return render_template("login.html",alert="Please login to access the website")
    else:
        sessionid = request.args["sessionid"]
    if not checksession(sessionid):
            return render_template("login.html",alert="Session id does not exist, please login again")
    path = request.args["path"]

    userconfig = LoadUserConfig(sessionid)
    AddLog(action=f"Settings opened",sessionid=sessionid,level="INFO")
    return render_template("settings.html", sessionid=sessionid, alert="", path=path, \
    overwritefile=userconfig["overwritefile"],allowdelete=userconfig["allowdelete"] )

@app.route("/settings/save")
def savesettings():
    if "sessionid" not in request.args:
        return render_template("login.html",alert="Please login to access the website")
    else:
        sessionid = request.args["sessionid"]
    if not checksession(sessionid):
            return render_template("login.html",alert="Session id does not exist, please login again")
    path = request.args["path"]

    allowdelete = "allowdelete" in request.args
    overwritefile = "overwritefile" in request.args
    configdata = {
        "allowdelete": allowdelete,
        "overwritefile": overwritefile
    }
    username = GetUsername(sessionid)
    with open(f"{config.defaultdir}/{username}/systemfiles/{username}.config.json", "w") as userconfig:
        json.dump(configdata,userconfig)
    AddLog(action=f"Settigs saved",sessionid=sessionid,level="INFO")
    return render_template("settings.html", sessionid=sessionid, \
    alert="Settings saved", path=path, allowdelete=allowdelete, overwritefile=overwritefile)



@app.route("/addfolder")
def addfolder():
    if "sessionid" not in request.args:
        return render_template("login.html",alert="Please login to access the website")
    else:
        sessionid = request.args["sessionid"]
    if not checksession(sessionid):
            return render_template("login.html",alert="Session id does not exist, please login again")
    path = request.args["path"]

    if not checkpath(sessionid,path):
        return index(sessionid=sessionid,alert = "You are not allowed to access the directory")
    
    name = request.args["foldername"]
    fullpath = os.path.join(path, name)
    if os.path.exists(fullpath):
        if os.path.isdir(fullpath):
            AddLog(action=f"This folder already exists : {fullpath}",sessionid=sessionid,level="WARNING")
            return index(alert="This folder already exists!",path=path,sessionid=sessionid)
        else:
            AddLog(action=f"File with the same name exists : {fullpath}",sessionid=sessionid,level="WARNING")
            return index(alert="File with the same name already exists!",path=path,sessionid=sessionid)
    else:
        try:
            os.mkdir(fullpath)
            AddLog(action=f"Created directory : {fullpath}",sessionid=sessionid,level="INFO")
        except:
            AddLog(action=f"Cannot create a folder",sessionid=sessionid,level="ERROR")
            return index(alert="Cannot create the folder",path=path,sessionid=sessionid)
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

    if not checkpath(sessionid,path):
        return index(sessionid=sessionid, alert = "You are not allowed to access the directory")

    asattachment = request.args["attachment"]
    print(asattachment)
    try:
        AddLog(action=f"File downloaded : {path}/{file}",sessionid=sessionid,level="INFO")
        return send_from_directory(path,file, as_attachment=asattachment)
    except:
        AddLog(action="Cannot download the file",sessionid=sessionid,level="WARNING")
        return index("Error. File cannot be downloaded or opened")


@app.route('/upload', methods=['POST'])
def upload():
    if "sessionid" not in request.form:
        return render_template("login.html",alert="Please login to access the website")
    else:
        sessionid = request.form["sessionid"]
    if not checksession(sessionid):
        return render_template("login.html",\
        alert="Session id does not exist or is expired, please login again")
    
    path = request.form["path"]

    if not checkpath(sessionid,path):
        return index(sessionid=sessionid,alert = "You are not allowed to access the directory")

    if 'file' not in request.files:
        return index(alert = "No file sent.", sessionid=sessionid, path=path)
    file = request.files['file']
    if file.filename == '':
        AddLog(action="No file selected for the upload",sessionid=sessionid,level="WARNING")
        return index("No file selected", sessionid=sessionid, path=path)
    if os.path.exists(f"{path}/{file.filename}"): #nie dziala
        return index(path=path,sessionid=sessionid,alert="File already exists")
    filename = secure_filename(file.filename)
    file.save(os.path.join(path, filename))
    AddLog(action=f"File uploaded to : {path}/{filename}",sessionid=sessionid,level="INFO")
    return index(path=path,sessionid=sessionid)


@app.route("/delete")
def delete():
    if "sessionid" not in request.args:
        return render_template("login.html",alert="Please login to access the website")
    else:
        sessionid = request.args["sessionid"]
    if not checksession(sessionid):
        return render_template("login.html",alert="Session id does not exist, please login again")
    userconfig = LoadUserConfig(sessionid)
    if not userconfig["allowdelete"]:
        AddLog(action="Deleting is disabled in your settings",sessionid=sessionid,level="INFO")
        return index(sessionid=sessionid)
    path = request.args["path"]
    file = request.args["file"]
    fullpath = os.path.join(path,file)

    if not checkpath(sessionid,fullpath):
        
        return index(sessionid=sessionid,path=config.defaultdir + "/" + GetUsername(sessionid),\
        alert = "You are not allowed to access the directory")
    
    os.remove(fullpath)
    AddLog(action="Deleted : " + fullpath,sessionid=sessionid,level="INFO")
    return index(sessionid=sessionid)

@app.route("/deletedir")
def deletedir():
    if "sessionid" not in request.args:
        return render_template("login.html",alert="Please login to access the website")
    else:
        sessionid = request.args["sessionid"]
    if not checksession(sessionid):
            return render_template("login.html",alert="Session id does not exist, please login again")
    if not LoadUserConfig(sessionid)["allowdelete"]:
        return index(sessionid=sessionid)
    path = request.args["path"]
    file = request.args["dir"]
    fullpath = os.path.join(path,file)

    username = GetUsername(sessionid)

    if not checkpath(sessionid,fullpath):
        AddLog(action="Cannot access the directory : " + fullpath ,level='WARNING',sessionid=sessionid)
        return index(sessionid=sessionid,path=config.defaultdir + "/" + username,\
        alert = "You are not allowed to access the directory")

    if  os.path.exists(fullpath):
        
        if os.path.isdir(fullpath):
            if len(os.listdir(fullpath)) > 0:
                if "allowdelete" not in request.args:
                    return render_template("deletefolder.html",sessionid=sessionid,path=path,dir=file,)
                else:
                    try:
                        shutil.rmtree(fullpath)
                        AddLog(action="Folder deleted : " + fullpath ,level='INFO',sessionid=sessionid)
                        return index(path=path,sessionid=sessionid)
                    except:
                        AddLog(action="Cannot delete the folder. Permission denied : " + fullpath ,level='ERROR',sessionid=sessionid)
                        return index(path=path,sessionid=sessionid,alert="Error. Permision denied")
            else:
                try:
                    shutil.rmtree(fullpath)
                    AddLog(action="Folder deleted : " + fullpath ,level='INFO',sessionid=sessionid)
                    return index(path=path,sessionid=sessionid)
                except:
                    AddLog(action="Cannot delete the folder. Permission denied : " + fullpath ,level='ERROR',sessionid=sessionid)
                    return index(path=path,sessionid=sessionid,alert="Error. Permision denied")
                
        else:
            AddLog(action="This is not a folder : " + fullpath ,level='WARNING',sessionid=sessionid)
            return index(alert="This is not a folder",path=path,sessionid=sessionid)
    else:
        AddLog(action="Folder does not exist : " + fullpath ,level='WARNING',sessionid=sessionid)
        return index(alert="Folder does not exist",path=path,sessionid=sessionid)
    
    

@app.route("/login", methods=['POST'])
def login(alert=""):
    username = request.form["login"]
    password = request.form["password"]
    with sqlite3.connect("db/hashes.db") as hashes:
        hashes.execute("delete from sessionid where sessionlifetime < datetime('now')")
        hashed = hashes.execute("select * from hashes where hashes.username = :username",{"username":username}).fetchall()
        if len(hashed) == 0:
            AddLog(action="Failed login",level='WARNING')
            return render_template("login.html",alert="Username or password is not correct. Please try again")
        hashcheck = bcrypt.checkpw(password.encode('utf-8'), hashed[0][2].encode('utf-8'))
        if hashcheck:
            sessionid = str(uuid.uuid4())
            hashes.execute(f"insert into sessionid values(:username,:sessionid,datetime('now', '+{config.SESSION_LIFETIME} minutes'))", {"username":username, "sessionid":sessionid})
            hashes.commit()
            AddLog(action="User login",sessionid=sessionid,level="INFO")
            return index(sessionid=sessionid)
        else:
            AddLog(action="Failed login. Incorrect password",level='WARNING')
    return render_template("login.html", alert="Username or password is not correct. Please try again")


@app.route("/logout")
def logout():
    sessionid=request.args["sessionid"]
    AddLog(action="Logout",level='INFO',sessionid=sessionid)
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
        newuser.execute("insert into adminpermission(username,admin) values(:username,False)",{"username":username})
        newuser.commit()
    #default user files
    userpath = config.defaultdir + "/" + username
    shutil.copytree("./userblueprint",userpath)
    os.rename(userpath+"/systemfiles/username.config.json",userpath+"/systemfiles/" + username +".config.json")
    AddLog(action=f"Account created",username=username,level="INFO")
    return render_template("login.html",alert="Account was created, please login")

@app.route("/loadlogs")
def loadlogs():
    if "sessionid" not in request.args:
        return render_template("login.html",alert="Please login to access the website")
    else:
        sessionid = request.args["sessionid"]
    if not checksession(sessionid):
            return render_template("login.html",alert="Session id does not exist, please login again")
    path = request.args["path"]
    username = GetUsername(sessionid)
    with open(f"{config.defaultdir}/{username}/systemfiles/userlogs.log","r") as logs:
        userlogs = [line.strip() for line in logs.readlines()]
        userlogs.reverse()
        AddLog(action="Logs opened",sessionid=sessionid,level="INFO")
        return render_template("logs.html",sessionid=sessionid,path=path,userlogs=userlogs)

@app.route("/loadadminlogs")
def loadadminlogs():
    if "sessionid" not in request.args:
        return render_template("login.html",alert="Please login to access the website")
    else:
        sessionid = request.args["sessionid"]
    if not checksession(sessionid):
            return render_template("login.html",alert="Session id does not exist, please login again")
    if not IsUserAdmin(sessionid):
        return index(alert="You lack permissions to access these logs.",sessionid=sessionid)
    path = request.args["path"]
    with open("./logs/serverlogs.log","r") as logs:
        logs = [line.strip() for line in logs.readlines()]
        logs.reverse()
        AddLog(action="Admin Logs opened",sessionid=sessionid,level="INFO")
        return render_template("logs.html",sessionid=sessionid,path=path,userlogs=logs)


def getuserpath(path):
    return path.split("users",1)[1]

def databasecreation():
    hashes = sqlite3.connect("db/hashes.db")
    hashes.execute("create table if not exists hashes(id intiger primary key, username text UNIQUE, hash text)")
    hashes.execute("create table if not exists sessionid(username text , sessionid text, sessionlifetime datetime)")
    hashes.execute("create table if not exists adminpermission(username text , admin bool)") #id intiger foreign key references id from hashes,
    hashes.close()

def checksession(sessionid):
    with sqlite3.connect("db/hashes.db") as checksession:
        result = checksession.execute("select * from sessionid where sessionid=:sessionid and sessionlifetime > datetime('now')",{"sessionid":sessionid}).fetchall()
        if len(result) == 0:
            AddLog(action=f"Session expired for id : {sessionid}",sessionid=sessionid,level="INFO")
            checksession.execute(f"delete * from sessionid where sessionid={sessionid}")
            return False
        checksession.execute(f"update sessionid set sessionlifetime=datetime('now', '+{config.SESSION_LIFETIME} minutes') where sessionid=:sessionid",{"sessionid":sessionid})
        checksession.commit()
    return True

def checkpath(sessionid,path):
    username = GetUsername(sessionid)
    splitpath = path.split(username,1)
    if IsUserAdmin(sessionid):
        return True
    if len(splitpath) != 2:
        AddLog(action="You cannot access the directory",sessionid=sessionid,level="WARNING")
        return False
    if splitpath[0] + "/" + username  != os.path.join(config.defaultdir,username):
        return True
    AddLog(action="You cannot access the directory",sessionid=sessionid,level="WARNING")
    return False

def GetUsername(sessionid):
    with sqlite3.connect("db/hashes.db") as username:
        username = username.execute(f"select username from sessionid where sessionid=:sessionid",{"sessionid":sessionid}).fetchall()[0][0]
    return username

def printip():
    print("----")
    try:
        print(request.environ['HTTP_X_FORWARDED_FOR']) # public client ip
    except:
        print("error")
    print("----")

def LoadUserConfig(sessionid):
    username = GetUsername(sessionid)
    defaultdir = config.defaultdir
    with open(f"{defaultdir}/{username}/systemfiles/{username}.config.json") as configfile:
        userconfig = json.load(configfile)
        return userconfig

def IsUserAdmin(sessionid):
    username = GetUsername(sessionid)
    with sqlite3.connect("db/hashes.db") as perms:
        adminperms = perms.execute("select admin from adminpermission where username=:username",{"username":username}).fetchall()[0][0]
    return adminperms

loggers = {"server": SetupLogger("server")}
def AddLog(sessionid=None, action="", level=None,username=None):
    logger = loggers["server"]

    if sessionid != None:
        if username==None:
            username = GetUsername(sessionid)
        if username in loggers.keys():
            logger = loggers[username]
        else:
            logger = SetupLogger(username,f"{config.defaultdir}/{username}/systemfiles/userlogs.log")
            loggers[username] = logger
    
    if level == 'WARNING':
        logger.warning(action)
    elif level == 'ERROR':
        logger.error(action)
    else:
        logger.info(action)

