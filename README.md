# fileshark


# Run webservice

To run the webservice, use command : flask --app service.py run 
to run in debug mode use --debug
default port is 5000
to run on different port, use --port <portnumber>
example : flask --app service.py run --debug --port 5001


# Used libraries :
flask
os
signal
werkzeug.utils
sqlite3
bcrypt
uuid
shutil
json