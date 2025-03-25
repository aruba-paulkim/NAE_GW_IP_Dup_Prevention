# -*- coding:utf-8 -*-
#
# (c) Copyright 2017-2021,2024 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

# Debug Info 
# start-shell
# journalctl -f | grep hpe-policyd

# Login failed:session limit reached.
# https-server session close all 

# clear nae-data

import requests, json, re, traceback, inspect
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LONG_DESCRIPTION = '''
'''

Manifest = {
    'Name':'gw_ip_dup_prevention',
    'Description':'Gateway IP Duplication Prevention',
    'Version':'0.9',
    'Author':'Paul Kim'
}

ParameterDefinitions = {
    'eventlog_check_interval':{
        'Name':'EventLog Check Interval',
        'Description':'EventLog Check Interval (min:15sec)',
        'Type':'String',
        'Default':'15'
    },
    'eventlog_since_minutes':{
        'Name':'EventLog Since Minutes',
        'Description':'EventLog Since Minutes',
        'Type':'String',
        'Default':'1'
    },
    'neighbor_switch_userid':{
        'Name':'neighbor_switch_userid',
        'Description':'neighbor_switch_userid',
        'Type':'String',
        'Default':'admin'
    },
    'neighbor_switch_userpw':{
        'Name':'neighbor_switch_userpw',
        'Description':'neighbor_switch_userpw',
        'Type':'String',
        'Default':'password'
    }
}


class Policy(NAE):

    def __init__(self):
        eventlog_check_interval = self.params['eventlog_check_interval'].value
        self.r1 = Rule("GW IP Dup") 
        self.r1.condition(f"every {eventlog_check_interval} seconds") # min 15 sec
        self.r1.action(self.eventlog_monitor)


    def eventlog_monitor(self, event):
        print(f"===== start =====================================")
        dup_sw_port = []
        n_minute_ago = int(self.params['eventlog_since_minutes'].value)

        url = f"{HTTP_ADDRESS}/rest/v1/logs/event" # OK
        # url = f"{HTTP_ADDRESS}/rest/v10.04/logs/event" # 404 Fail
        # url = f"{HTTP_ADDRESS}/rest/latest/logs/event" # 404 Fail
        url += "?priority=3&EVENT_CATEGORY=NDM"
        url += f"&since={n_minute_ago} minutes ago"
        print(f"[{inspect.currentframe().f_code.co_name}] url:{url}")
        res = requests.get(url)
        j_res = json.loads(res.text)

        if j_res['entityCounts']['total'] == 0:
            print(f"[{inspect.currentframe().f_code.co_name}] No LOGs(priority=3, EVENT_CATEGORY=NDM, since={n_minute_ago} minutes ago)")
            return ""

        print(f"[{inspect.currentframe().f_code.co_name}] Total Eventlog Count:{j_res['entityCounts']['total']}")

        set_dupinfo = set()
        for log in j_res['entities']:
            if "Duplicate IP" in log['MESSAGE']:
                ip_pattern = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', log['MESSAGE'])
                vlan_pattern = re.search(r'vlan(\d+)', log['MESSAGE'])
                mac_pattern = re.search(r'([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})', log['MESSAGE'])

                ip_address = ip_pattern.group(1) if ip_pattern else "Not found"
                vlan = vlan_pattern.group(1) if vlan_pattern else "Not found"
                mac_address = mac_pattern.group(1) if mac_pattern else "Not found"
                dict_dup = {'ip':ip_address,'vlan':vlan, 'mac':mac_address }
                set_dupinfo.add(frozenset(dict_dup.items()))

        print(f"[{inspect.currentframe().f_code.co_name}] set_dupinfo:{set_dupinfo}")
        self.check_mactable(set_dupinfo)


    def check_mactable(self, dupinfo):
        sess = requests.Session()
        neighbor_ip = ""
        try:
            for item in dupinfo:
                dict_item = dict(item)
                print(f"[{inspect.currentframe().f_code.co_name}] dup info ip:{dict_item['ip']}, vlan:{dict_item['vlan']}, mac:{dict_item['mac']}")

                port = self.get_port_info_by_mac(dict_item['mac'], dict_item['vlan'])
                if port == "":
                    continue
                
                interface = self.get_interface_by_port(port, dict_item)
                if interface == "":
                    continue
                
                neighbor_ip = self.get_lldp_neighbors_by_interface(interface)
                if neighbor_ip == "":
                    continue

                (sess, login) = self.check_neighbor_ip_login(sess, neighbor_ip)
                if login == "":
                    continue

                neighbor_port = self.get_neighbor_port_info_by_mac(sess, neighbor_ip, dict_item['vlan'], dict_item['mac'])
                if neighbor_port == "":
                    continue

                neighbor_port_down = self.get_neighbor_port_admin_down(sess, neighbor_ip, neighbor_port)
                if neighbor_port_down == "":
                    continue

        except Exception as e:
            print(f"[{inspect.currentframe().f_code.co_name}] Exception:{e}")
            print(traceback.format_exc())
        finally:
            print(f"[{inspect.currentframe().f_code.co_name}] finally neighbor_ip:{neighbor_ip}, {sess.cookies}")
            if sess.cookies:
                # url = f"https://{neighbor_ip}/rest/v1/logout" #410 Gone
                url = f"https://{neighbor_ip}/rest/v10.04/logout" #404 Not Found
                # url = f"https://{neighbor_ip}/rest/latest/logout" #404 Not Found
                print(f"[{inspect.currentframe().f_code.co_name}] logout:{url}")
                res = sess.request("POST", url, verify=False)
                if res.status_code == 200:
                    print(f"[{inspect.currentframe().f_code.co_name}] logout OK, text:{res.text}, {sess.cookies}")
                else :
                    print(f"[{inspect.currentframe().f_code.co_name}] ERROR:Unknown response, status_code:{res.status_code}, text:{res.text}")

            sess.close()


    def get_port_info_by_mac(self, mac_address, vlan):
        data = ""
        url = f"{HTTP_ADDRESS}/rest/v10.04/system/vlans/*/macs/dynamic,{mac_address}"
        print(f"[{inspect.currentframe().f_code.co_name}] url:{url}")
        res = requests.get(url)
        if res.status_code == 200:
            j_res = json.loads(res.text)
            if vlan in j_res:
                vlan_data = j_res[vlan]
                mac_data = vlan_data[f"dynamic,{mac_address}"]
                if 'port' in mac_data:
                    data = mac_data['port']
                else:
                    print(f"[{inspect.currentframe().f_code.co_name}] ERROR:NO port attribute")
            else:
                print(f"[{inspect.currentframe().f_code.co_name}] ERROR:NO {vlan} attribute")
            
            print(f"[{inspect.currentframe().f_code.co_name}] OK:{data}")
        elif res.status_code == 404:
            print(f"[{inspect.currentframe().f_code.co_name}] ERROR:(404) No MAC Address info")
        else:
            print(f"[{inspect.currentframe().f_code.co_name}] ERROR:Unknown response, status_code:{res.status_code}, text:{res.text}")
        
        return data


    def get_interface_by_port(self, port, dup_info):
        data = ""
        for key, value in port.items():
            interface_id = key
            url = f"{HTTP_ADDRESS}{value}" 
            print(f"[{inspect.currentframe().f_code.co_name}] url:{url}")
            res = requests.get(url)
            if res.status_code == 200:
                j_res = json.loads(res.text)
                if "is_network_port" in j_res:
                    is_network_port_data = j_res['is_network_port']
                    if "lldp_reported" in is_network_port_data:
                        lldp_reported = is_network_port_data['lldp_reported']
                        if lldp_reported: # lldp_reported is True -> neighbor switch
                            if "interfaces" in j_res:
                                data = j_res['interfaces']
                                for dkey, dvalue in data.items():
                                    print(f"[{inspect.currentframe().f_code.co_name}] lldp_reported({lldp_reported})->Neighbor Switch : {dkey}, {dvalue}")
                                    return dkey
                            else :
                                print(f"[{inspect.currentframe().f_code.co_name}] ERROR:NO interfaces attribute")
                        else: # lldp_reported is False -> direct connected PC
                            msg = f"{interface_id} port shutdown, vlan:{dup_info['vlan']}, mac:{dup_info['mac']}, ip:{dup_info['ip']}"
                            print(f"[{inspect.currentframe().f_code.co_name}] lldp_reported({lldp_reported})->Direct Connected PC : {interface_id} port shutdown")
                            cli = f"configure terminal\ninterface {interface_id}\nshutdown\nend\n"
                            print(f"[{inspect.currentframe().f_code.co_name}] {interface_id} shutdown cli:\n{cli}")
                            ActionCLI(cli)
                            ActionSyslog(msg, severity=SYSLOG_WARNING)

                            # Need Alert?
                            # if self.get_alert_level() is None:
                            #     self.set_alert_level(AlertLevel.CRITICAL)
                    else:
                        print(f"[{inspect.currentframe().f_code.co_name}] ERROR:NO is_network_port.lldp_reported attribute")
                else:
                    print(f"[{inspect.currentframe().f_code.co_name}] ERROR:NO is_network_port attribute")
            else:
                print(f"[{inspect.currentframe().f_code.co_name}] ERROR:Unknown response, status_code:{res.status_code}, text:{res.text}")

        return data


    def get_lldp_neighbors_by_interface(self, interface):
        data = ""
        url = f"{HTTP_ADDRESS}/rest/v10.04/system/interfaces/{interface.replace('/', '%2F')}/lldp_neighbors"
        print(f"[{inspect.currentframe().f_code.co_name}] interface url:{url}")
        res = requests.get(url)
        if res.status_code == 200:
            j_res = json.loads(res.text)
            for key, value in j_res.items():
                print(f"[{inspect.currentframe().f_code.co_name}] response:{key}, {value}")
                lldp_neighbors_url = value

                url = f"{HTTP_ADDRESS}{lldp_neighbors_url}"
                print(f"[{inspect.currentframe().f_code.co_name}] neighbors url:{url}")
                res = requests.get(url)
                if res.status_code == 200:
                    j_res = json.loads(res.text)
                    if "neighbor_info" in j_res:
                        neighbor_info = j_res['neighbor_info']
                        data = neighbor_info['mgmt_ip_list']
                        print(f"[{inspect.currentframe().f_code.co_name}] neighbors ip :{data}")
                        return data
                    else :
                        print(f"[{inspect.currentframe().f_code.co_name}] ERROR:NO neighbor_info attribute")
                else:
                    print(f"[{inspect.currentframe().f_code.co_name}] ERROR:Unknown response, status_code:{res.status_code}, text:{res.text}")
        else:
            print(f"[{inspect.currentframe().f_code.co_name}] ERROR:Unknown response, status_code:{res.status_code}, text:{res.text}")
        
        return data


    def check_neighbor_ip_login(self, sess, neighbor_ip):
        if not sess.cookies:
            url = f"https://{neighbor_ip}/rest/v10.04/login"
            userid = self.params['neighbor_switch_userid'].value
            userpw = self.params['neighbor_switch_userpw'].value
            payload = {"username":f"{userid}", "password":f"{userpw}"}
            print(f"[{inspect.currentframe().f_code.co_name}] neighbor login:{url}")
            res = sess.request("POST", url, data=payload, verify=False)

            if res.status_code == 401: # Unauthorized
                if 'session limit reached' in res.text:
                    print(f"[{inspect.currentframe().f_code.co_name}] Login failed:session limit reached -> https-server session close all ")

                if 'Login failed.' in res.text:
                    print(f"[{inspect.currentframe().f_code.co_name}] Login failed:Worng userid or userpw.")

                ActionSyslog(f'401, Unauthorized : {neighbor_ip}')
                if self.get_alert_level() is None:
                    self.set_alert_level(AlertLevel.MAJOR)
                    
                return (sess, "")
            elif res.status_code == 200:# Success login
                print(f"[{inspect.currentframe().f_code.co_name}] neighbor login OK:{sess.cookies}")
                if self.get_alert_level() is not None:
                    self.remove_alert_level()
                return (sess, "OK")
            else:
                print(f"[{inspect.currentframe().f_code.co_name}] ERROR:Unknown response, status_code:{res.status_code}, text:{res.text}")
                return (sess, "")
        else:
            print(f"[{inspect.currentframe().f_code.co_name}] sess.cookies exists. Maybe already logged in:{sess.cookies}")
            if self.get_alert_level() is not None:
                self.remove_alert_level()
            return (sess, "OK")

        return (sess, "")

        
    def get_neighbor_port_info_by_mac(self, sess, neighbor_ip, vlan, mac_address):
        data = ""
        url = f"https://{neighbor_ip}/rest/v10.04/system/vlans/*/macs/dynamic,{mac_address}"
        print(f"[{inspect.currentframe().f_code.co_name}] url:{url}")
        res = sess.request("GET", url, verify=False)
        if res.status_code == 200:
            j_res = json.loads(res.text)
            if vlan in j_res:
                vlan_data = j_res[vlan]
                if f"dynamic,{mac_address}" in vlan_data:
                    mac_data = vlan_data[f"dynamic,{mac_address}"]
                    if 'port' in mac_data:
                        data = mac_data['port']
                        return data
                    else:
                        print(f"[{inspect.currentframe().f_code.co_name}] ERROR:NO port attribute")
                else:
                    print(f"[{inspect.currentframe().f_code.co_name}] ERROR:NO dynamic,{mac_address} attribute")
            else:
                print(f"[{inspect.currentframe().f_code.co_name}] ERROR:NO {vlan} attribute")
        elif res.status_code == 404:
            print(f"[{inspect.currentframe().f_code.co_name}] ERROR:(404) No MAC Address info")
        else:
            print(f"[{inspect.currentframe().f_code.co_name}] ERROR:Unknown response, status_code:{res.status_code}, text:{res.text}")
        
        return data


    def get_neighbor_port_admin_down(self, sess, neighbor_ip, neighbor_port):
        data = ""
        for key, value in neighbor_port.items():
            print(f"[{inspect.currentframe().f_code.co_name}] neighbor_port:{key}, {value}")
            interface_id = key

            url = f"https://{neighbor_ip}/rest/v10.04/system/interfaces/{interface_id.replace('/', '%2F')}"
            print(f"[{inspect.currentframe().f_code.co_name}] url:{url}")
            payload = json.dumps({"admin":"down"})
            res = sess.request("PATCH", url, data=payload, verify=False)
            if res.status_code == 204:
                print(f"[{inspect.currentframe().f_code.co_name}] {interface_id} admin down Success.")
                return "OK"
            else:
                print(f"[{inspect.currentframe().f_code.co_name}] ERROR:Unknown response, status_code:{res.status_code}, text:{res.text}")
        
        return data

