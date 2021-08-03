import json, requests, ssl, time, urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class AQ:
    def __init__(self):
        self.APIURL = "https://localhost:13443/api/v1/" #acunetix api url (last "/" required)
        self.hostname = "localhost" #acunetix machine hostname
        self.APIKey = "1986ad8c0a5b3df4d7028d5f3c06e936cd1a3223b184b49e2877adacd573554e4"
        self.scanProfileID = "11111111-1111-1111-1111-111111111111" #fullscan by default
        self.requestsHeaders = {"X-Auth":self.APIKey, "Content-Type":"application/json", "Accept":"application/json"}
        self.pool = urllib3.PoolManager(cert_reqs="CERT_NONE", assert_hostname=self.hostname,)

    def getTargetList(self):
        targetReq = self.pool.request("GET", self.APIURL + "targets", '', self.requestsHeaders)
        
        if targetReq.status != 200:
            print("some error while getting targets")
            print(targetReq.status, targetReq.data.decode("utf-8"))
            return

        targetData = json.loads(targetReq.data.decode("utf-8"))
        
        for target in range(len(targetData["targets"])):
            configurationReq = self.pool.request("GET", self.APIURL + "targets/" + targetData["targets"][target]["target_id"] + "/configuration", headers = self.requestsHeaders)
            if configurationReq.status != 200:
                print("some error while getting target #" + str(target + 1) + "configuration")
                print(configurationReq.status, configurationReq.data.decode("utf-8"))
                return

            configurationData = json.loads(configurationReq.data.decode("utf-8"))
            proxyStatus = ""
            if configurationData["proxy"]["enabled"] == False:
                proxyStatus = "proxy disabled"
            else:
                proxyStatus = "proxy enabled"

            print(str(target + 1) + ". host:", targetData["targets"][target]["address"], "| decription:", targetData["targets"][target]["description"], "|", proxyStatus)

    def addTarget(self):
        targetReq = self.pool.request("GET", self.APIURL + "targets", '', self.requestsHeaders)
        if targetReq.status != 200:
            print("some error while getting target")
            print(targetReq.data.decode("utf-8"))
            return

        targetData = json.loads(targetReq.data.decode("utf-8"))
        if len(targetData["targets"]) > 499:
            print("at most 500 targets available, cant add another one")
            return

        print("hostname:")
        newTargetHostname = input()
        print("description: ")
        newTargetDesription = input()

        addReq = self.pool.request("POST", 
                          self.APIURL + "targets", 
                          body = json.dumps({"address": newTargetHostname, "description": newTargetDesription, "type": "default", "criticality": 10}), 
                          headers=self.requestsHeaders)
        
        if addReq.status != 201:
            print("some error while adding target")
            print(addReq.data.decode("utf-8"))
            return

    def addProxyToTarget(self):
        print("select the target")

        targetsIDs = []
        targetReq = self.pool.request("GET", self.APIURL + "targets", '', self.requestsHeaders)
        if targetReq.status != 200:
            print("some error while getting targets info")
            print(targetReq.status, targetReq.data.decode("utf-8"))
            return

        targetData = json.loads(targetReq.data.decode("utf-8"))
        for target in range(len(targetData["targets"])):
            targetsIDs.append(targetData["targets"][target]["target_id"])
            print(str(target + 1) + ". host: " + targetData["targets"][target]["address"], "| " + targetData["targets"][target]["description"])
        targetNum = int(input())
        targetID = targetsIDs[targetNum - 1]

        print("proxy address:")
        proxyAddress = input()
        print("proxy port:")
        proxyPort = int(input())
        print("proxy login (empty w/o authorization)")
        proxyLogin = input()
        print("proxy pass (empty w/o authorization)")
        proxyPass = input()

        targetConfiguration = json.dumps({"proxy": {"protocol": "http", "address": proxyAddress, "port": proxyPort, "username": proxyLogin, 
                                        "password": proxyPass, "enabled": True}})

        targetConfigurationReq = self.pool.request("PATCH", self.APIURL + "targets/" + targetID + "/configuration", 
        body = targetConfiguration, headers=self.requestsHeaders)

        if targetConfigurationReq.status != 204:
            print("some error while updating target configuration")
            print(targetConfigurationReq.data.decode("utf-8"))

    def removeTarget(self):
        print("select the target")

        targetsIDs = []
        targetReq = self.pool.request("GET", self.APIURL + "targets", '', self.requestsHeaders)
        if targetReq.status != 200:
            print("some error while getting targets info")
            print(targetReq.status, targetReq.data.decode("utf-8"))
            return

        targetData = json.loads(targetReq.data.decode("utf-8"))
        for target in range(len(targetData["targets"])):
            targetsIDs.append(targetData["targets"][target]["target_id"])
            print(str(target + 1) + ". host: " + targetData["targets"][target]["address"], "| " + targetData["targets"][target]["description"])
        targetNum = int(input())
        targetID = targetsIDs[targetNum - 1]

        req = self.pool.request("DELETE", self.APIURL + "targets/" + targetID, headers=self.requestsHeaders)
        
        if not (req.status == 200 or req.status == 204):
            print("some error while deleting target")
            print(req.data.decode("utf-8"))

    def getScanList(self):
        scanReq = self.pool.request("GET", self.APIURL + "scans", '', self.requestsHeaders)
        if scanReq.status != 200:
            print("some error while getting scans")
            print(scanReq.status, scanReq.data.decode("utf-8"))
            return

        scanData = json.loads(scanReq.data.decode("utf-8"))
        
        for scan in range(len(scanData["scans"])):
            print(str(scan + 1) + ". host:", scanData["scans"][scan]["target"]["address"], "| status:", scanData["scans"][scan]["current_session"]["status"],
                "| progress:", scanData["scans"][scan]["current_session"]["progress"], "| high/medium/low/info vulns found:", 
                str(scanData["scans"][scan]["current_session"]["severity_counts"]["high"]) + "/" + str(scanData["scans"][scan]["current_session"]["severity_counts"]["medium"]) +
                "/" + str(scanData["scans"][scan]["current_session"]["severity_counts"]["low"]) + "/" + str(scanData["scans"][scan]["current_session"]["severity_counts"]["info"]))

    def addScan(self):
        print("select the target")

        targetsIDs = []
        targetReq = self.pool.request("GET", self.APIURL + "targets", '', self.requestsHeaders)
        if targetReq.status != 200:
            print("some error while getting targets info")
            print(targetReq.status, targetReq.data.decode("utf-8"))
            return

        targetData = json.loads(targetReq.data.decode("utf-8"))
        for target in range(len(targetData["targets"])):
            configurationReq = self.pool.request("GET", self.APIURL + "targets/" + targetData["targets"][target]["target_id"] + "/configuration", headers=self.requestsHeaders)
            if configurationReq.status != 200:
                print("some error while getting target #" + str(target + 1) + "configuration info")
                print(configurationReq.status, configurationReq.data.decode("utf-8"))
                return

            configurationData = json.loads(configurationReq.data.decode("utf-8"))
            proxyStatus = ""
            if configurationData["proxy"]["enabled"] == False:
                proxyStatus = "proxy disabled"
            else:
                proxyStatus = "proxy enabled"

            print(str(target + 1) + ". host:", targetData["targets"][target]["address"], "| decription:", targetData["targets"][target]["description"], "|", proxyStatus)
            targetsIDs.append(targetData["targets"][target]["target_id"])

        targetNum = int(input())
        targetID = targetsIDs[targetNum - 1]
        
        print("select the scan profile")

        scanProfileIDs = []
        scanProfileReq = self.pool.request("GET", self.APIURL + "scanning_profiles", '', self.requestsHeaders)
        if scanProfileReq.status != 200:
                print("some error while getting scan profiles info")
                print(scanProfileReq.status, scanProfileReq.data.decode("utf-8"))
                return

        scanProfileData = json.loads(scanProfileReq.data.decode("utf-8"))
        for scanProfile in range(len(scanProfileData["scanning_profiles"])):
            print(str(scanProfile + 1) + ".", scanProfileData["scanning_profiles"][scanProfile]["name"])
            scanProfileIDs.append(scanProfileData["scanning_profiles"][scanProfile]["profile_id"])

        scanNum = int(input())
        scanID = scanProfileIDs[scanNum - 1]

        bodyJson = json.dumps({"target_id": targetID, "profile_id": scanID, 
            "schedule": {"disable": False,"start_date": None,"time_sensitive": False}})
        scanReq = self.pool.request("POST", self.APIURL + "scans", body=bodyJson, headers=self.requestsHeaders)
        if scanReq.status != 201:
            print("some error while adding new scan")
            print(scanReq.status, scanReq.data.decode("utf-8"))
            return

    def getScanReport(self):
        print("select scan")
        scanReq = self.pool.request("GET", self.APIURL + "scans", '', self.requestsHeaders)
        if scanReq.status != 200:
            print("some error while getting scans")
            print(scanReq.status, scanReq.data.decode("utf-8"))
            return

        scanData = json.loads(scanReq.data.decode("utf-8"))
        scanIDs = []
        
        for scan in range(len(scanData["scans"])):
            print(str(scan + 1) + ". host:", scanData["scans"][scan]["target"]["address"], "| status:", scanData["scans"][scan]["current_session"]["status"],
                "| progress:", scanData["scans"][scan]["current_session"]["progress"], "| high/medium/low/info vulns found:", 
                str(scanData["scans"][scan]["current_session"]["severity_counts"]["high"]) + "/" + str(scanData["scans"][scan]["current_session"]["severity_counts"]["medium"]) +
                "/" + str(scanData["scans"][scan]["current_session"]["severity_counts"]["low"]) + "/" + str(scanData["scans"][scan]["current_session"]["severity_counts"]["info"]))

            scanIDs.append(scanData["scans"][scan]["current_session"]["scan_session_id"])
        
        scanNum = int(input())
        scanID = scanIDs[scanNum - 1]
        

        bodyJson = json.dumps({"template_id": "11111111-1111-1111-1111-111111111111", "source": {"list_type": "scan_result", "id_list": [scanID]}})
        reportReq = self.pool.request("POST", self.APIURL + "reports", body = bodyJson, headers = self.requestsHeaders)
        if reportReq.status != 201:
            print("some error while adding report")
            print(reportReq.status, reportReq.data.decode("utf-8"))
            return

        reportData = json.loads(reportReq.data.decode("utf-8"))
        reportID = reportData["report_id"]
        downloadLink = None
        
        while downloadLink == None:
            scanReq = self.pool.request("GET", self.APIURL + "reports/" + reportID, '', self.requestsHeaders)
            scanData = json.loads(scanReq.data.decode("utf-8"))
            downloadLink = scanData["download"]
            time.sleep(1)

        print("download link:", self.APIURL + downloadLink[0][8:])

    def removeScan(self):
        print("select scan:")
        scanReq = self.pool.request("GET", self.APIURL + "scans", '', self.requestsHeaders)
        scanData = json.loads(scanReq.data.decode("utf-8"))
        scanIDs = []
        
        for scan in range(len(scanData["scans"])):
            print(str(scan + 1) + ". host:", scanData["scans"][scan]["target"]["address"], "| status:", scanData["scans"][scan]["current_session"]["status"],
                "| progress:", scanData["scans"][scan]["current_session"]["progress"], "| high/medium/low/info vulns found:", 
                str(scanData["scans"][scan]["current_session"]["severity_counts"]["high"]) + "/" + str(scanData["scans"][scan]["current_session"]["severity_counts"]["medium"]) +
                "/" + str(scanData["scans"][scan]["current_session"]["severity_counts"]["low"]) + "/" + str(scanData["scans"][scan]["current_session"]["severity_counts"]["info"]))
            scanIDs.append(scanData["scans"][scan]["scan_id"])

        scanNum = int(input())
        scanID = scanIDs[scanNum - 1]

        scanReq = self.pool.request("DELETE", self.APIURL + "scans/" + scanID, headers = self.requestsHeaders)
        
        if scanReq.status != 204:
            print("some error while deleting scan")
            print(scanReq.status, scanReq.data.decode("utf-8"))


    def start(self):
        print("------------------------------------------------------")
        print("1. target list")
        print("2. add target")
        print("3. add proxy to target")
        print("4. remove target")
        print("5. scan list")
        print("6. create scan")
        print("7. scan report")
        print("8. remove scan")
        print("------------------------------------------------------")

        option = int(input())
        while not (option > 0 and option < 11):
            print("wrong number")
            option = input()
        
        if option == 1:
            self.getTargetList()
        elif option == 2:
            self.addTarget()
        elif option == 3:
            self.addProxyToTarget()
        elif option == 4:
            self.removeTarget()
        elif option == 5:
            self.getScanList()
        elif option == 6:
            self.addScan()
        elif option == 7:
            self.getScanReport()
        elif option == 8:
            self.removeScan()


def main():
    aq = AQ()
    while True:
        aq.start()

if __name__ == "__main__":
    main()