import json
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib import hub
from random import randint,seed
from time import time


#Custom Event for time out
class EventMessage(event.EventBase):
    '''Create a custom event with a provided message'''
    def __init__(self, message):
        print("Creating Event")
        super(EventMessage, self).__init__()
        self.msg=message

#Main Application
class MovingTargetDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _EVENTS = [EventMessage] 
    R2V_Mappings={"10.0.0.1":"","10.0.0.2":"","10.0.0.3":"","10.0.0.4":"","10.0.0.5":"","10.0.0.6":"","10.0.0.7":"","10.0.0.8":""}
    V2R_Mappings={} 
    AuthorizedEntities=['10.0.0.1']
    Resources=["10.0.0.9","10.0.0.10","10.0.0.11","10.0.0.12",
           "10.0.0.13","10.0.0.14","10.0.0.15","10.0.0.16",
           "10.0.0.17","10.0.0.18","10.0.0.19","10.0.0.20",
           "10.0.0.21","10.0.0.22","10.0.0.23","10.0.0.24",
           "10.0.0.25","10.0.0.26","10.0.0.27","10.0.0.28",
           "10.0.0.29","10.0.0.30","10.0.0.31","10.0.0.32",
           "10.0.0.33","10.0.0.34","10.0.0.35","10.0.0.36"]
    def start(self):
        '''
            Append a new thread which calls the TimerEventGen function which generates timeout events
            every 30 seconds & sends these events to its listeners
            Reference: https://sourceforge.net/p/ryu/mailman/ryu-devel/?viewmonth=201601&viewday=12
        '''
        super(MovingTargetDefense,self).start()
        self.threads.append(hub.spawn(self.TimerEventGen))
            
    def TimerEventGen(self):
        
        '''
            A function which generates timeout events every 30 seconds
            & sends these events to its listeners
            Reference: https://sourceforge.net/p/ryu/mailman/ryu-devel/?viewmonth=201601&viewday=12
        '''
        while 1:
            self.send_event_to_observers(EventMessage("TIMEOUT"))
            hub.sleep(30)
    
    def __init__(self, *args, **kwargs):
        '''Constructor, used to initialize the member variables'''
        super(MovingTargetDefense, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths=set()
        self.HostAttachments={}
        self.offset_of_mappings=0
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def handleSwitchFeatures(self, ev):
        '''
            Handles switch feature events sent by the switches to the controller
            the first time switch sends negotiation messages.
            We store the switch info to the datapaths member variable
            & add table miss flow entry to the switches.
            
            #Reference: Simple_Switch
            #http://ryu.readthedocs.io/en/latest/writing_ryu_app.html
        '''
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths.add(datapath);
        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
          
    def EmptyTable(self,datapath):
        '''
            Empties flow table of a switch!
            Remove Flow rules from switches
            Reference: https://sourceforge.net/p/ryu/mailman/message/32333352/
        '''
        ofProto=datapath.ofproto
        parser = datapath.ofproto_parser
        match=parser.OFPMatch()
        flow_mod=datapath.ofproto_parser.OFPFlowMod(datapath,0,0,0,ofProto.OFPFC_DELETE,0,0,1,ofProto.OFPCML_NO_BUFFER,ofProto.OFPP_ANY,ofProto.OFPG_ANY,0,match=match,instructions=[])
        datapath.send_msg(flow_mod)
        
    #Listen to timeout & update the mappings
    @set_ev_cls(EventMessage)
    def update_resources(self,ev):
        '''
            Listen to the Time-out event & update the real-virtual IP address mappings from the resources
            Also remove the flow rules from all the switches.
            & Add a default, table-miss entry to all the switches.
            
        '''
        '''seed function is used initialize random number generator. The current system time is seeded to
        obtain different set of random numbers every time the function runs.'''  
        seed(time())
        pseudo_ranum = randint(0,len(self.Resources)-1) #randint returns a random integer in the range of 0 and len(Resources)-1
        print ("Random Number:",pseudo_ranum)

        for keys in self.R2V_Mappings.keys():
            #Virtual IP address are assigned to each host from the pool of Resources starting from (pseudo_ranum)th index
            self.R2V_Mappings[keys]=self.Resources[pseudo_ranum]
            #pseudo_ranum is updated to point to next index. If the index is overshooted from the Resources pool, it is looped back to point to 0th index  
            pseudo_ranum=(pseudo_ranum+1)%len(self.Resources)    
        self.V2R_Mappings = {v: k for k, v in self.R2V_Mappings.items()}
        print "**********", self.R2V_Mappings,"***********"
        print "**********", self.V2R_Mappings,"***********"
        '''
            Reference: https://sourceforge.net/p/ryu/mailman/message/32333352/
            How to remove flowrules from switches
        '''
        for curSwitch in self.datapaths:
            #Remove all flow entries
            parser = curSwitch.ofproto_parser
            match=parser.OFPMatch()
            flowModMsg=self.EmptyTable(curSwitch)
            #Add default flow rule
            ofProto=curSwitch.ofproto
            actions = [parser.OFPActionOutput(ofProto.OFPP_CONTROLLER,
                                          ofProto.OFPCML_NO_BUFFER)]
            self.add_flow(curSwitch, 0, match, actions)
        
    def isRealIPAddress(self,ipAddr):
        '''Returns True id IP address is real'''
        if ipAddr in self.R2V_Mappings.keys():
            return True
    
    def isVirtualIPAddress(self,ipAddr):
        ''' Returns True if the IP address is virtual'''
        if ipAddr in self.R2V_Mappings.values():
            return True
        
    '''def isAuthorizedEntity(self,ipAddr):
        if ipAddr in self.AuthorizedEntities:
            return True'''
        
    def isDirectContact(self,datapath,ipAddr):
        '''
            Return true if the IP addr host is directky connected to the switch given
            Also assumes that the host is directly connected if it has no information in the hostAttachments Table
        '''
        if ipAddr in self.HostAttachments.keys():
            if self.HostAttachments[ipAddr]==datapath:
                return True
            else:
                return False
        return True
         
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=None):
        '''
            Adds flow rules to the switch 
            Reference: Simple_Switch
            http://ryu.readthedocs.io/en/latest/writing_ryu_app.html
        '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id :
            if hard_timeout==None:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, hard_timeout=hard_timeout)
        else:
            if hard_timeout==None:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    #Packet Handler ICMP & ARP
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def handlePacketInEvents(self, ev):
        '''
            Handles Incoming Packets & implements Random Host mutation technique
            by changing src & dst IP addresses of the incoming packets.
            Some part of the code is inspired by Simple_Switch
            http://ryu.readthedocs.io/en/latest/writing_ryu_app.html 
        '''
        actions=[]
        pktDrop=False
        
               
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
            
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        arp_Obj=pkt.get_protocol(arp.arp)# Extract ARP object from packet
        icmp_Obj=pkt.get_protocol(ipv4.ipv4)# Extract ICMP object packet
        
        if arp_Obj:
            '''Handles ARP packets'''
            src=arp_Obj.src_ip
            dst=arp_Obj.dst_ip
            
            '''
                To Implement a Learning MTD, there is a need to know, to which switch, the host is directly connected to.
                So the first time an ARP packet comes in who's src address is real, we store the IP addr-Switch DPID mapping
                into the member variable HostAttachments.
            '''
            if self.isRealIPAddress(src) and src not in self.HostAttachments.keys():
                self.HostAttachments[src]=datapath.id
                
            '''
                Learning MTD implementation
                if src is real change it to virtual no matter wat.
                if dest doesn't have a mapping in my table change to real and flood.
                    This happens only for the first time when we donot know
                    to which switch, the destination host is directly connected to.
                if dst is virtual check if dest is directly connected then change it to real
                else let it pass unchanged.
            '''
            
            if self.isRealIPAddress(src):
                match=parser.OFPMatch(eth_type=0x0806,in_port=in_port,arp_spa=src,arp_tpa=dst)
                spa = self.R2V_Mappings[src] 
                print("Changing SRC REAL IP "+src+"---> Virtual SRC IP "+spa)
                actions.append(parser.OFPActionSetField(arp_spa=spa))
                
            if self.isVirtualIPAddress(dst):
                match=  parser.OFPMatch(eth_type=0x0806,in_port=in_port,arp_tpa=dst,arp_spa=src)
                if self.isDirectContact(datapath=datapath.id,ipAddr=self.V2R_Mappings[dst]):
                    keys = self.V2R_Mappings.keys() 
                    tpa = self.V2R_Mappings[dst] 
                    print("Changing DST Virtual IP "+dst+"---> REAL DST IP "+tpa)
                    actions.append(parser.OFPActionSetField(arp_tpa=tpa))
                    
            elif self.isRealIPAddress(dst):
                '''Learn MTD From Flood'''
                match=parser.OFPMatch(eth_type=0x0806,in_port=in_port,arp_spa=src,arp_tpa=dst)
                if not self.isDirectContact(datapath=datapath.id,ipAddr=dst):
                    pktDrop=True
                    print "Dropping from",dpid
            else:
                pktDrop=True
        elif icmp_Obj:
            '''Handles ICMP packets'''
            print("ICMP PACKET FOUND!")
            src=icmp_Obj.src
            dst=icmp_Obj.dst
            
            if self.isRealIPAddress(src) and src not in self.HostAttachments.keys():
                self.HostAttachments[src]=datapath.id
            
            '''
                Learning MTD implementation
                if src is real change it to virtual no matter wat.
                if dest doesn't have a mapping in my table change to real and flood.
                    This happens only for the first time when we donot know
                    to which switch, the destination host is directly connected to.
                if dst is virtual check if dest is directly connected then change it to real
                else let it pass unchanged.
            '''
            
            if self.isRealIPAddress(src):         
                match=  parser.OFPMatch(eth_type=0x0800,in_port=in_port,ipv4_src=src,ipv4_dst=dst)
                ipSrc = self.R2V_Mappings[src]
                print("Changing SRC REAL IP "+src+"---> Virtual SRC IP "+ipSrc)
                actions.append(parser.OFPActionSetField(ipv4_src=ipSrc))
            if self.isVirtualIPAddress(dst):
                #print self.HostAttachments
                match=  parser.OFPMatch(eth_type=0x0800,in_port=in_port,ipv4_dst=dst,ipv4_src=src)
                if self.isDirectContact(datapath=datapath.id,ipAddr=self.V2R_Mappings[dst]):
                    ipDst = self.V2R_Mappings[dst] 
                    print("Changing DST Virtual IP "+dst+"---> Real DST IP "+ipDst)
                    actions.append(parser.OFPActionSetField(ipv4_dst=ipDst))
            
            elif self.isRealIPAddress(dst):
                '''Learn From Flood'''
                match=parser.OFPMatch(eth_type=0x0806,in_port=in_port,arp_spa=src,arp_tpa=dst)
                if not self.isDirectContact(datapath=datapath.id,ipAddr=dst):
                    pktDrop=True
                    print "Dropping from",dpid
            else:
                pktDrop=True
                    
        '''Extract Ethernet Object from packet'''                    
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        '''Store the incoming packet source address, switch & the port combination to be used to learn the packet switching'''
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        
        '''learn a mac address to avoid FLOOD next time.'''
        
        self.mac_to_port[dpid][src] = in_port
        '''Learning Mac implemention to avoid flood'''
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        '''Append the outport action to the action set'''
        if not pktDrop:
            actions.append(parser.OFPActionOutput(out_port))
        '''install a flow to avoid packet_in next time'''
        if out_port != ofproto.OFPP_FLOOD:
            '''
                verify if we have a valid buffer_id, if yes avoid to send both flow_mod & packet_out
                Install Flow rules to avoid the packet in message for similar packets.
            '''
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions,msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)    
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        '''
            Build a packet out message & send it to the switch with the action set,
            Action set includes all the IP addres changes & out port actions.
        '''
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        '''Send the packet out message to the switch'''
        datapath.send_msg(out)
