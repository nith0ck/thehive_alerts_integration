"""
Author: Romenige Pinto
"""

import sys
import json
import logging
import requests
import msal
import email
import bs4
import pandas as pd
import uuid


config = json.load(open(sys.argv[1]))
gbls= json.load(open("globals.json"))
parentFolderId = ''
childFolderId  = ''
userId = ""

thehiveURL = ""
thehiveApiKey=''

result = None
t_id  = ''
s_add = ''
d_add = ''

try:
    from thehive4py.api import TheHiveApi
    from thehive4py.models import Case, CaseTask, CaseObservable, CustomFieldHelper
    from thehive4py.models import Alert, AlertArtifact
except:
    log.error("Please install thehive4py.")
    sys.exit(1)


def authenticate():
    app = msal.ConfidentialClientApplication(
            config["client_id"], authority=config["authority"],
            client_credential=config["secret"]
       )

    result = app.acquire_token_silent(config["scope"], account=None)


    if not result:
        logging.info("No suitable token exists in cache. Let's get a new one from ADD.")
        result = app.acquire_token_for_client(scopes=config["scope"])

    return result

def getMail(result):
    if "access_token" in result:
        endpoint = config["endpoint"]+'/'+userId+'/mailFolders/'+parentFolderId+'/childFolders/'+childFolderId+'/messages?filter=isRead eq false'
        #endpoint = config["endpoint"]+'/'+userId+'/mailFolders/'+parentFolderId+'/childFolders/'
        headers={'Authorization': 'Bearer ' + result["access_token"],'Content-Type': 'application/json'}
        response = requests.get(endpoint, headers=headers)

        if response.status_code == 200:
            response_json = response.json()
            #print(response_json)
            
            response_json = response.json()
            #print (response_json.keys())
            response_json['@odata.context']

            emails = response_json['value']
            #print(len(emails))

            for email in emails:
                updateMail(email, result)
                return email
            
    else:
        tokenError(result)



def tokenError(result):
     print(result.get("error"))
     print(result.get("error_description"))
     print(result.get("correlation_id"))

     return None



def updateMail(email, result):
    obj = {"messageId" : email['id']}
    msgId = email['id']

    endpoint = config["endpoint"]+'/'+userId+'/mailFolders/'+parentFolderId+'/childFolders/'+childFolderId+'/messages/'+msgId
    headers={'Authorization': 'Bearer ' + result["access_token"], 'Content-type': 'application/json'}

    response = requests.patch(endpoint, json={"isRead": 'true'}, headers=headers)

    
def getData(msg):
    
    lst = []
    content = msg['body']['content'].split("\"")
    #content = content[len(content)-1]    
    n_data = []
    for ct in range(len(content)):
        if   ct==0: n_data.append(content[ct].split(","))
        elif ct==1: n_data.append(content[ct])
        elif ct==2: n_data.append(content[ct].split(","))
        elif ct==3: n_data.append(content[ct])
        elif ct==4: n_data.append(content[ct].split(","))
    
    n_data[0].pop()
    n_data[2].pop(0)
    n_data[2].pop()
    
    return n_data
    

    

def formData(data, fields): 
    form =  {}
    ps=0
    for i in range(len(data)):
        if type(data[i]) is list: 
            for j in range(len(data[i])):
                ps+=1
                form[ps] = (data[i][j])
        if type(data[i]) is str:
            ps+=1
            form[ps] = (data[i])
    


    return(mergeData(form, fields))

def mergeData(data, fields):
    lst = []
    struct = {}

    for item in data.values():
        lst.append(item)
     
    for i in range(len(fields)):
        struct[fields[i]] = lst[i]
    
    return struct
    
    
def getFields():
    lst = []
    with open('fields.txt', 'r') as fld:
        for string in fld:
            lst = string.replace('"','').split(",")
    return lst
    
def getContrast(data):
    dsc = []
    obj = {' Receive Time':data[' Receive Time'],' Type': data[' Type'],' Action':data[' Action'],' Threat/Content Type':data[' Threat/Content Type'],' Source Address':data[' Source Address'], ' Destination Address':data[' Destination Address'], ' Source User':data[' Source User'],' Destination User':data[' Destination User'],' URL/Filename':data[' URL/Filename'], ' Threat Category':data[' Threat Category'], ' Application Characteristic':data[' Application Characteristic']}

    for x, y in obj.items():
        dsc.append(x+ ": "+y)
    
    dsc.append(json.dumps(data))
    description = "\n\n".join(dsc)
    
    return description
 

def getDescription(msg):
    description = []
    data   = getData(msg)
    fields = getFields()
    dta = formData(data, fields)
    
    outcome = beforeSubmit(dta)
     
    return(getContrast(dta), dta, outcome)

    
def getSeverity(data):
    svr_dict = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4 }
    
    for key in svr_dict:
        if key == data[' Severity']:
            return svr_dict[key]

def beforeSubmit(data):
    default_action = 'sinkhole'
    outcome = None

    if (data[' Action'] == default_action):
        if gbls["threat_id"]==data[' Threat ID'] and gbls["src_add"]==data[' Source Address']: 
            outcome=False
        else:
            outcome=True
            updateVar(data[' Threat ID'],data[' Source Address'], data[' Destination Address'] )
        
    else:
        if gbls["threat_id"]==data[' Threat ID'] and gbls["src_add"]==data[' Source Address'] and gbls["dst_add"]==data[' Destination Address']:
             outcome=False
        else:
            outcome=True
            updateVar(data[' Threat ID'],data[' Source Address'], data[' Destination Address'] )
    
    return outcome


def updateVar(new_threat_id, new_src_add, new_dst_add):
    gbls["threat_id"] = new_threat_id
    gbls["src_add"]   = new_src_add
    gbls["dst_add"]   = new_dst_add

    with open('globals.json', 'w') as fl:
        json.dump(gbls, fl)
    fl.close()
    

def submitThehive(email):
    body, dta, outcome = getDescription(email)
    
    if (outcome is True):
        svr  =  getSeverity(dta)
        api = TheHiveApi(thehiveURL, thehiveApiKey)
        sourceRef = str(uuid.uuid4())[0:6]
        

        alert = Alert(title=email["subject"],tlp=2,description=body,severity=svr,type='external',source=' Paloalto Firewall <firewall@bancobai.cv>',sourceRef=sourceRef,tags=['Firewall','Threat',dta[' Action']])

        id = None
        response = api.create_alert(alert)
        print(response)
    
    else:
        print("No, same alert")
    
     

def main():
    result = authenticate()
    email = getMail(result)
    submitThehive(email)




if __name__ == '__main__':
    main()

