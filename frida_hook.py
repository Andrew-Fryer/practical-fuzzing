import sys

import frida


session = frida.attach("target_application")
file = open('./frida_agent.js', 'r')
script_str = file.read()
script = session.create_script(script_str)
def on_message(message, data):
    print(message)
script.on('message', on_message)
script.load()
sys.stdin.read()
