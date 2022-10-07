import logging
from queue import Queue
from dotenv import load_dotenv
from pathlib import Path
import threading
import datetime
from jinja2 import Template
from netmiko import ConnectHandler
import json
import time
import hashlib
import base64
import requests
import os

# TODO: Link the classes together
# TODO: Better exception handling
# TODO: Optimise the SSH connections, close connections
# TODO: Handle sites with multiple voice VLANs
# TODO: Reporting?
# TODO: zScaler config for LM API when inside the network
# TODO: What if no voice VLAN

log_name = datetime.datetime.now()
log_name = log_name.strftime("%d%b%y" + "-" "%H" + "." + "%M")

logger = logging.getLogger(__name__)

# Stream Handler
stream = logging.StreamHandler()
streamformat = logging.Formatter("%(levelname)s:%(module)s:%(lineno)d:%(message)s")
stream.setLevel(logging.DEBUG)
stream.setFormatter(streamformat)

# Adding all handlers to the logs
logger.propagate = False
logger.addHandler(stream)

env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)

ssh_user = os.environ['SSH_USER']  # TACACS Username
ssh_pwd = os.environ['SSH_PWD']  # TACACS Password
accessId = os.getenv("AccessId")  # LogicMonitor API Access ID
accessKey = os.getenv("AccessKey")  # LogicMonitor API Access Key

num_threads = 20  # number of simultaneous threads, how many devices to process at once (Number of switches at once)
enclosure_queue = Queue()
print_lock = threading.Lock()


class SwitchOutput(Exception):  # Catch exceptions silently for prod
    pass


class LogicMonitor:  # Object for handling all LogicMonitor queries
    def __init__(self, accessId, accessKey, queryParams, resourcePath, siteId):
        import hmac  # Build the API Query
        httpVerb = 'GET'
        data = ''
        url = 'https://se.logicmonitor.com/santaba/rest' + resourcePath + queryParams
        epoch = str(int(time.time() * 1000))
        requestVars = httpVerb + epoch + data + resourcePath
        hmac = hmac.new(accessKey.encode(), msg=requestVars.encode(),
                        digestmod=hashlib.sha256).hexdigest()  # Encode the API query
        signature = base64.b64encode(hmac.encode())
        auth = 'LMv1 ' + accessId + ':' + signature.decode() + ':' + epoch
        headers = {'Content-Type': 'application/json', 'Authorization': auth}
        try:  # Attempt an API Call
            logger.info("LogicMonitor API Call")
            response = requests.get(url, data=data, headers=headers)
        except Exception as e:
            logger.warning("Cannot connect to the LM API")
            logger.debug(e)
        try:  # Verify the response from LM is OK
            i = response.json()
            logger.info("LogicMonitor API return is OK!")
            logger.debug(i)
        except Exception as e:
            logger.error("LogicMonitor API return was not readable")
            logger.debug(e)
            exit(404)
        self.siteId = siteId
        self.output = i  # Put the output from LM into something that can be shared throughout the object

    def device_List(self):  # Retrieve device list and cleanse the data
        logger.info("LogicMonitor Get API Call")
        get_device_list = self.output["data"]["items"]
        logger.debug(get_device_list)
        ipAddress = False
        deviceType = False
        country = False
        device_list = []
        sanitised_device_list = []
        logger.info("sanitise data (siteID)")

        for device in get_device_list:
            logger.debug(device)
            for device_property in device["inheritedProperties"]:
                if device_property["name"] == "ctag.siteid":
                    if int(self.siteId) == int(device_property["value"]):
                        logger.debug("device matched to siteID, adding to sanitised: " + device["displayName"])
                        sanitised_device_list.append(device)
        for device in sanitised_device_list:
            ipAddress = device["name"]
            logger.debug(device)
            for custom_property in device["customProperties"]:
                if custom_property["name"] == "ctag.devicetype":
                    deviceType = custom_property["value"]
            for inherited_property in device["inheritedProperties"]:
                if inherited_property["name"] == "ctag.country":
                    country = inherited_property["value"]
            device_list.append({"id": device["id"],
                                "deviceName": device["displayName"],
                                "ipAddress": ipAddress,
                                "country": country,
                                "deviceType": deviceType})
            ipAddress = False
            deviceType = False

        out = [i for i in device_list if ("Switch - Access" in i["deviceType"])]  # Only return devices with "Switch - Access"  \\ Changed from "Switch" 5 Oct 2022.
        logger.debug(out)
        return out


class SwitchConnector():
    def __init__(self, host, username, password, config_set):
        self.host = host["ipAddress"]
        self.country = host["country"]
        self.username = username
        self.password = password
        self.config_set = config_set
        self.ping = os.system("ping -c 1 -w2 " + self.host + " > /dev/null 2>&1")
        self.protocol = "cisco_ios"  # Start with SSH, fail to Telnet, and finally ERROR
        logger.debug(self.ping)
        self.output_interfaces = False
        self.ios_version = False
        self.model = False
        self.voice_vlan = host["voice_vlan"]
        self.vlans = host["vlans"]

    def DeviceDiscovery(self):
        output = False
        logger.debug("Device Discovery, protocol is set to " + self.protocol)
        if self.protocol == "cisco_ios":
            logger.info("Trying with SSH")
            try:
                with ConnectHandler(ip=self.host,
                                    username=self.username,
                                    password=self.password,
                                    device_type=self.protocol) as ch:
                    output = ch.send_config_set(self.config_set)
                    ch.disconnect()
            except Exception as e:

                logger.debug(e)
                self.protocol = "cisco_ios_telnet"

        if self.protocol == "cisco_ios_telnet":
            logger.info("Trying with Telnet")
            try:
                with ConnectHandler(ip=self.host,
                                    username=ssh_user,
                                    password=ssh_pwd,
                                    device_type='cisco_ios_telnet') as ch:
                    output = ch.send_config_set(self.config_set)
                    ch.disconnect()

            except Exception as e:
                logger.debug(e)
                self.protocol = "ERROR"
                # TODO: DO I NEED TO RETURN AN ERROR HERE??????
        logger.warning("resulting protocol was: " + self.protocol)
        if not output:
            logger.info(self.host + ": NO OUTPUT RETURNED FROM SWITCH")
            raise SwitchOutput("No output was returned from the host " + self.host)
        show_interfaces = output.split("sh int status | i /")[
            1].splitlines()  # Split the interface status output into a variable
        show_version = output.split("sh int status | i")[0].splitlines()  # Split the sh ver output into a variable

        for line in show_version:
            if ", Version " in line:
                if len(line.split(",")) == 2:
                    self.ios_version = line.split(",")[1].split(" ")[
                        2].strip()  # get the version number, remove whitespace
                elif len(line.split(",")) == 4:
                    self.ios_version = line.split(",")[2].split(" ")[
                        2].strip()  # get the version number, remove whitespace

            if "Model number" in line:
                self.model = line.split(":")[1].strip()  # get the Model Number, remove whitespace
        output_interfaces = []
        logger.info("model is: " + str(self.model))
        logger.info("version is: " + str(self.ios_version))

        for interface in show_interfaces:
            interface_name = False  # Avoid duplicates by setting to False at the start of each iteration
            vlan_id = False
            if interface:
                interface = interface.split(" ")
                interface_name = interface[0]
                for element in interface:
                    try:
                        vlan_id = int(element)
                    except ValueError:
                        logger.debug(element)
                        continue
            if interface_name and vlan_id:
                output_interfaces.append({"interface_name": interface_name, "vlan_id": vlan_id})
        logger.debug(output_interfaces)
        final_output = {"model": self.model, "version": self.ios_version, "protocol": self.protocol,
                        "interfaces": output_interfaces}
        return final_output


class SwitchConfigurator:
    def __init__(self, host, username, password):
        self.host = host["ipAddress"]
        self.country = host["country"]
        self.username = username
        self.password = password
        self.protocol = host["protocol"]  # Protocol recorded from first connection
        self.output_interfaces = host["interfaces"]
        self.voice_vlan = host["voice_vlan"]
        self.vlans = host["vlans"]

    def GlobalConfigPush(self):

        with open("settings.json") as file:
            settings = json.load(file)
        logger.info(settings)
        # Begin templating
        with open("config/Global-NewGen.jinja", "r") as global_file:
            global_config = global_file.read()
        t = Template(global_config)
        region = settings["region_finder"][0][self.country]
        settings = settings["region_settings"][region][0]
        configuration = t.render(settings).splitlines()
        logger.debug(configuration)

        logger.info("Trying with " + self.protocol)
        try:
            with ConnectHandler(ip=self.host,
                                username=self.username,
                                password=self.password,
                                device_type=self.protocol) as ch:
                output = ch.send_config_set(configuration)
                ch.disconnect()
        except Exception as e:
            logger.critical("ERROR: executing global config on " + self.host + e)
            logger.critical(i)
            self.protocol = "ERROR"
        return output
        # return configuration  # TODO: Protective measure

    def InterfaceConfigPush(self):

        # Begin templating
        with open("config/Interface-NewGen.jinja", "r") as global_file:
            global_config = global_file.read()  # TODO: Fix Naming, interface not global
        t = Template(global_config)
        voice_vlan = {"voice_vlan": self.voice_vlan}  # Build dictionary for JINJA template
        configuration = t.render(voice_vlan).splitlines()
        self.vlans = [int(x) for x in self.vlans]  # Turn the elements into integers
        out = [x for x in self.output_interfaces if x["vlan_id"] in self.vlans]  # Only include interfaces that are in the vlan list
        n = 4  # Number of interfaces to configure at once
        output = [out[i:i + n] for i in range(0, len(out), n)]  # Build lists of 4 interfaces
        interface_range = []

        for i in output:  # Build the interface range list, add the interface template
            index = len(i)
            string = "interface range "
            while index != 0:
                if index == 1:
                    string += i[index - 1]["interface_name"]
                else:
                    string += i[index - 1]["interface_name"] + ", "
                index -= 1
            result = [string]
            for line in configuration:
                result.append(line)
            interface_range.append(result)
        try:  # deploy config
            with ConnectHandler(ip=self.host,
                                username=self.username,
                                password=self.password,
                                device_type=self.protocol) as ch:
                for i in interface_range:  # TODO: Speed up iteration
                    output = ch.send_config_set(i)
                    logger.critical("executing " + self.host + ", " + str(i[0]))
                ch.disconnect()
        except Exception as e:
            logger.critical("ERROR: executing interface config on " + self.host + e)
            logger.critical(i)
            self.protocol = "ERROR"
            # TODO: DO I NEED TO RETURN AN ERROR HERE??????
        return output


def device_connector(i, q):
    while True:
        try:
            host = q.get()
            logger.debug("host" + str(host))
            logger.critical("Thread for: " + host["deviceName"])
            config_set = ["end", "show ver", "sh int status | i /"]  # Discovery commands, need end to exit conf t mode
            discovery = SwitchConnector(host=host, username=ssh_user, password=ssh_pwd,
                                        config_set=config_set).DeviceDiscovery()
            if not discovery:
                discovery = {}
            host = {**host, **discovery}
            SwitchConfigurator(host=host, username=ssh_user, password=ssh_pwd).GlobalConfigPush()
            SwitchConfigurator(host=host, username=ssh_user, password=ssh_pwd).InterfaceConfigPush()
            logger.critical("discovery finished: " + host["deviceName"])
        except SwitchOutput as e:
            logger.critical("not output was returned for " + host["ipAddress"])
            logger.debug(e)
        finally:
            q.task_done()


def main():
    with open('input.json', 'r') as file:
        json_file = json.load(file)
    for site in json_file:
        voice_vlan = site["voice_vlan"]
        vlans = site["vlans"]
        if site["mode"] == "IP":
            identifier = 0
            ip_output = []
            for host in site["ips"]:
                identifier += 1
                ip_output.append({
                    "id": identifier,
                    "deviceName": host,
                    "ipAddress": host,
                    "country": site["country"],
                    "deviceType": "Switch"
                })
            site["device_list"] = ip_output
        elif site["mode"] == "LM":

            queryParams = '?filter=systemProperties.name:system.staticgroups,systemProperties.value~*Network*-' + str(
                site["siteID"])
            resourcePath = '/device/devices'
            lm_out = LogicMonitor(accessKey=accessKey, accessId=accessId, queryParams=queryParams,
                                  resourcePath=resourcePath,
                                  siteId=site["siteID"]).device_List()
            site["device_list"] = lm_out
        for i in range(num_threads):
            thread = threading.Thread(target=device_connector, args=(i, enclosure_queue,))
            thread.setDaemon(True)
            thread.start()
        logger.debug(site)
        for host in site["device_list"]:
            host["vlans"] = vlans
            host["voice_vlan"] = voice_vlan
            enclosure_queue.put(host)

        enclosure_queue.join()
        return  # Maintain this return
    return


if __name__ == '__main__':
    """
    
    LOGGING MATRIX:
                        This logging level will display logs from the categories in the rows
                        info    warning     debug   critical    error   
    logger.info          X                    X
    logger.warning       X         X          X
    logger.debug                              X
    logger.critical      X         X          X        X          X
    logger.exception     X         X          X                   X
    logger.error         X         X          X                   X
    
    debug is most verbose,
    info is 2nd most verbose
    warning is 3rd most verbose
    error is 4th most verbose
    critical is the least verbose
    
    """

    start_time = time.time()
    main()
    run_time = time.time() - start_time
    logger.critical("** Time to run: %s sec" % round(run_time, 2))
