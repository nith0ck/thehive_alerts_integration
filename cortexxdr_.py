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
parentFolderId = ''
childFolderId = ''
userId = ""

thehiveURL = ""
thehiveApiKey=''

result = None


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
        headers={'Authorization': 'Bearer ' + result["access_token"],'Content-Type': 'application/json'}
        response = requests.get(endpoint, headers=headers)

        if response.status_code == 200:
            response_json = response.json()
            #print (response_json.keys())
            response_json['@odata.context']

            emails = response_json['value']
            #print(len(emails))

            for email in emails:
                #return email
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
    
    if response.status_code == 200:
        print ('Email marked as read')
    

def getSource(df):
    source = df[0][2]
    return source
    
def cleanMessage(msg):
    
    soup = bs4.BeautifulSoup(msg,'lxml')
    table = soup.find_all('table')
    df = pd.read_html(str(table))    
    
    table = df[2]
    source = getSource(table)
    
 
    if (len(table)== 12):
        if source == "Source:XDR Analytics" or source=="Source:XDR Analytics BIOC":
            table = table[0][11]
            table = ' '.join(table.split())
            obj = json.loads(table)
            return obj, source
        elif source == "Source:XDR Agent":
            table = table[0][11]
            table = ' '.join(table.split())
            obj = json.loads(table)
            return obj, source

    elif(len(table) == 11):
        if source == "Source:XDR Analytics" or source=="Source:XDR Analytics BIOC":
            table = table[0][10]
            table = ' '.join(table.split())
            obj = json.loads(table)
            return obj, source


def severidade(msg):
    svr_dict = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4 }
    df = getDataframe(msg)
    df = df[2]
    sv = df[0][1]
    #print (sv)
    for key in svr_dict:
        if key == sv:
            return svr_dict[key]

def getDataframe(msg):
    soup = bs4.BeautifulSoup(msg['body']['content'],'lxml')
    table = soup.find_all('table')
    df = pd.read_html(str(table))
        
    return df

def getDescription(msg):

    obj, source = cleanMessage(msg['body']['content']) 
    df = getDataframe(msg)
    df = df[2]

    json_object = json.dumps(obj, indent = 4)
    description = []
    
    if (source == "Source:XDR Analytics BIOC"):
                #print (df[0][l])
        for i in range(0, len(df)-1):
            description.append(df[0][i])
        
        obj_dict = {
            "detection_method " : obj['original_alert_json']['_detection_method'],
            "alert_source " : obj['original_alert_json']['alert_source'],
            "alert_category " : obj['original_alert_json']['alert_category'],
            "alert_name " : obj['original_alert_json']['alert_name'],
            "alert_description": obj['original_alert_json']['alert_description'],
                }
    elif source == "Source:XDR Analytics":
        
        for i in range(0, len(df)-1):
            description.append(df[0][i])
        
        obj_dict = {
            "alert_category": obj['original_alert_json']['alert_category'],
            "alert_name " : obj['original_alert_json']['alert_name'],
            "alert_source " : obj['original_alert_json']['alert_source'],
            "alert_description": obj['original_alert_json']['alert_description'],
            "alert_category " : obj['original_alert_json']['alert_category']
                }
    elif source == "Source:XDR Agent":
        key = 'apks'

        for i in range (0, len(df)-1):
            description.append(df[0][i])

        if key in obj['original_alert_json']['messageData']:
            obj_dict = {
                "agentIp": obj['original_alert_json']['endPointHeader']['agentIp'],
                "deviceName": obj['original_alert_json']['endPointHeader']['deviceName'],
                "userName": obj['original_alert_json']['endPointHeader']['userName'],
                "AppName": obj['original_alert_json']['messageData']['apks'][0]["appName"],
                "packageName": obj['original_alert_json']['messageData']['apks'][0]["packageName"],
                "SHA256": obj['original_alert_json']['messageData']['apks'][0]["sha256"],
            }

        elif key not in obj['original_alert_json']['messageData']:
            obj_dict = {
                    "alert_name " : obj['alert_name'],
                    "alert_category": obj['alert_category'],
                    "alert_description": obj['alert_description'],
                    "agentIp": obj['original_alert_json']['endPointHeader']['agentIp'],
                    "deviceName": obj['original_alert_json']['endPointHeader']['deviceName']
                    }

    #print(description)   
    description.append(json.dumps(obj_dict))
    x = "\n\n".join(description)
    return x
    

def submitThehive(email):
    body = getDescription(email)
    svr  = severidade(email)
    
    api = TheHiveApi(thehiveURL, thehiveApiKey)

    sourceRef = str(uuid.uuid4())[0:6]

    alert = Alert(title= email["subject"],tlp=2,description=body,severity=svr,type='external', source=' Cortex XDR <cortex@xdr.paloaltonetworks.com>', sourceRef=sourceRef, tags=['Cortex XDR'])
    
    id = None
    response = api.create_alert(alert)
    if response.status_code == 201:
        print('True')
    else:
        print('False')

def main():
    result = authenticate()
    email = getMail(result)
    submitThehive(email)
    #updateMail(email, result)
    

if __name__ == '__main__':
    main()
