import json
import requests
import urllib3
from base64 import b64encode
import sys
from datetime import datetime

def api (range_start, end_range, part_report):

    # Disable insecure https warnings (for self-signed SSL certificates)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Configuration
    protocol = 'https'
    host = ''
    port = 55000
    user = ''
    password = ''
    login_endpoint = 'security/user/authenticate'

    login_url = f"{protocol}://{host}:{port}/{login_endpoint}"
    basic_auth = f"{user}:{password}".encode()
    login_headers = {'Content-Type': 'application/json',
                    'Authorization': f'Basic {b64encode(basic_auth).decode()}'}

    response = requests.get(login_url, headers=login_headers, verify=False)
    token = json.loads(response.content.decode())['data']['token']

    requests_headers = {'Content-Type': 'application/json',
                        'Authorization': f'Bearer {token}'}

    #Write output to *.txt
    file_path = 'vulnerability.txt'
    sys.stdout = open(file_path, "w")

    #Date
    now = datetime.now()
    time = now.strftime("%Y/%m/%d %H:%M:%S")
    print('The report was generated at', time)

    print('VM\'s\' has the following vulnerabilities:')

    agent_range = list(range(range_start, end_range))  

    def response_last_scan (): 
        last_scan = []
        id = []
        for x in agent_range:
            response_last_scan = requests.get(f"{protocol}://{host}:{port}/vulnerability/{'%03d' % x}/last_scan?pretty=true", headers=requests_headers, verify=False)
            last_scan_json = response_last_scan.text
            last_scan_data = json.loads(last_scan_json)
            id1 = '%03d' % x
            last_scan1 = [i['last_full_scan'] for i in last_scan_data['data']['affected_items']]
            last_scan.append(last_scan1)
            id.append(id1)
        result = dict(zip(id, last_scan))
        return result
    last_scan = (response_last_scan())


    def response_name_id ():
        response_vm_name = requests.get(f"{protocol}://{host}:{port}/agents", headers=requests_headers, verify=False)
        vm_name_json = response_vm_name.text
        vm_name_data = json.loads(vm_name_json)
        agent_id = [str(i["id"]) for i in vm_name_data['data']['affected_items']]
        vm_name = [str(i["name"]) for i in vm_name_data['data']['affected_items']]
        return dict(zip(vm_name, agent_id))
    data_id_name = response_name_id()

    for y in agent_range:
        response = requests.get(f"{protocol}://{host}:{port}/vulnerability/{'%03d' % y}?pretty=true", headers=requests_headers, verify=False)
        str_json = response.text
        data = json.loads(str_json)
        all_id = list({'%03d' % y})
        a = [str(i) for i in all_id]
        for i in data_id_name:
            for h in last_scan:
                for j in a:
                    if j == h and j == data_id_name[i]:
                            for item in data['data']['affected_items']:
                                if item['severity'] == 'Critical' or item['severity'] == 'High':
                                    print('VM name:', i, '\n', item['severity'], item['title'], ", ".join(last_scan[h]))

    lines_seen = set() 
    with open("vulnerability.txt", "r+") as f:
        d = f.readlines()
        f.seek(0)
        for i in d:
            if i not in lines_seen:
                f.write(i)
                lines_seen.add(i)
        f.truncate()


    with open('vulnerability.txt', 'r') as f:
        lines = f.readlines()
        lines = lines[:-1]

    with open('vulnerability.txt', 'w') as f:
        f.writelines(lines)

    inputFile = open('vulnerability.txt', 'r')
    outputFile = open('vulnerability_new.txt', 'w')

    for line in inputFile:

        outputLine = line.strip() + '\n'
        if 'VM name:' in line:
            outputLine = '\n' +  outputLine
        outputFile.write(outputLine)
    

    inputFile.close()
    outputFile.close()

    # Form pdf report 
    # pip install fpdf
    from fpdf import FPDF 
    
    pdf = FPDF() 
    pdf.add_page() 
    pdf.set_font("Arial", size = 10) 
    f = open("vulnerability_new.txt", "r") 
    for x in f: 
        pdf.cell(200, 10, txt = x, ln = 1, align = 'L') 
    pdf.output(f"vulnerability_part_{part_report}.pdf")
    
    
api ()