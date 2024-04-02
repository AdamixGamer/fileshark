# fileshark


# Run webservice

To run the webservice, use command : flask --app service.py run  |
To run in debug mode use --debug |
Default port is 5000 |
To run on different port, use --port <portnumber> |
Example : flask --app service.py run --debug --port 5001 |


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