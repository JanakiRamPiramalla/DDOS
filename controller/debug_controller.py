"""
Minimal Debug Controller - Tests if packet_in handler is being called
"""
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types

class DebugController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DebugController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.packet_count = 0
        
        print("=" * 70)
        print("DEBUG CONTROLLER INITIALIZED")
        print("Waiting for switches and packets...")
        print("=" * 70)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        print(f"\n{'='*70}")
        print(f"SWITCH CONNECTED: DPID={datapath.id:016x}")
        print(f"{'='*70}")

        # Install table-miss flow
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)
        
        print(f"Table-miss flow installed on DPID={datapath.id:016x}")
        print(f"{'='*70}\n")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """THIS MUST BE CALLED WHEN PACKETS ARRIVE"""
        self.packet_count += 1
        
        print(f"\n{'*'*70}")
        print(f"🎉 PACKET #{self.packet_count} RECEIVED!")
        print(f"{'*'*70}")
        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            print("  (LLDP packet - ignoring)")
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        print(f"  DPID: {dpid}")
        print(f"  In Port: {in_port}")
        print(f"  MAC Src: {src}")
        print(f"  MAC Dst: {dst}")

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
            print(f"  Action: Forward to port {out_port}")
        else:
            out_port = ofproto.OFPP_FLOOD
            print(f"  Action: FLOOD")

        actions = [parser.OFPActionOutput(out_port)]

        # Send packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, 
            buffer_id=msg.buffer_id,
            in_port=in_port, 
            actions=actions, 
            data=data
        )
        datapath.send_msg(out)
        
        print(f"  ✅ Packet forwarded")
        print(f"{'*'*70}\n")
