from datetime import datetime
import random
import joblib  
import numpy as np  
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp
from ryu.lib import hub


protocolsDict = {
    "UDP" : 1,
    "IPv4" : 2, 
    "TCP" : 3,
    "ARP" : 4,
    "ICMPv6" : 5,
    "MDNS" : 6
}

ipDict = {
    "10.0.0.1" : 1,
    "10.0.0.2" : 2, 
    "10.0.0.3" : 3,
}

class SimpleSwitchIDS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchIDS, self).__init__(*args, **kwargs)
        self.mac_to_port = {}           # Per il MAC learning
        self.datapaths = {}             # Per salvare i datapath degli switch connessi
        self.counters = {}          # Per contare i pacchetti sospetti per IP

        # Inizializzo con gli indirizzi IP della nostra rete
        self.counters.setdefault("10.0.0.1", 0)
        self.counters.setdefault("10.0.0.2", 0)
        self.counters.setdefault("10.0.0.3", 0)

        # Inizializzo il modello
        self.kmeans_model = joblib.load('Dataset/modello_e_soglia.pkl')  
        self.threshold = 10             # Soglia per rilevamento attacco

        # Avvia un thread per resettare i contatori dei pacchetti ogni 10 secondi
        self.reset_thread = hub.spawn(self._reset_counters)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Gestisce l'evento di connessione di un nuovo switch.
        Installa la flow entry di "table-miss" e salva il datapath.
        """
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Installazione della flow entry di table-miss
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)
        
        # Tutti i pacchetti SYN devono andare al controller
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_flags=0x02)  # TCP SYN
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, priority=100, match=match, actions=actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        """
        Funzione di utility per installare una flow entry.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id is not None:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Gestisce l'evento Packet-In: esegue il MAC learning,
        analizza il pacchetto per eventuali comportamenti sospetti (ad es. SYN flood e UDP flood),
        e inoltra il pacchetto verso la porta corretta.
        """
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match.get('in_port')

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignora i pacchetti LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return


        # Controllo IDS
        ip_pkt = pkt.get_protocol(ipv4.ipv4)  # Estraggo il pacchetto IPv4
        tcp_pkt = pkt.get_protocol(tcp.tcp) # Estraggo il pacchetto TCP

        if ip_pkt and tcp_pkt and ip_pkt.src in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]: #Evita di controllare i pacchetti di nodi diversi
            self._syn_check(tcp_pkt, ip_pkt, pkt, datapath)
        elif ip_pkt and ip_pkt.src in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]:
            self._udp_check(ip_pkt, pkt, datapath)



        # Procedura di MAC learning
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        src = eth.src
        dst = eth.dst
        self.mac_to_port[dpid][src] = in_port
        #self.logger.info("Packet in - DPID: %s, SRC: %s, DST: %s, IN_PORT: %s",pid, src, dst, in_port)

        # Determina la porta di output (se l'indirizzo di destinazione è noto)
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Se la destinazione è nota, installa una flow entry per future corrispondenze
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, priority=1, match=match, actions=actions,
                              buffer_id=msg.buffer_id, idle_timeout=30)
                return
            else:
                self.add_flow(datapath, priority=1, match=match, actions=actions,
                              idle_timeout=30)

        # Inoltra il pacchetto
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
    

    """
    Funzioni di IDS
    """
    def _syn_check(self, tcp_pkt, ip_pkt, pkt, datapath): 
        """
            Estraggo dal pacchetto TCP le caratteristiche rilevanti per il modello
        """
        features = {
            "No.": tcp_pkt.seq,
            "Time": datetime.now().timestamp(),
            "Source": ip_pkt.src,
            "Destination": ip_pkt.dst,
            "Protocol": ip_pkt.proto,
            "Lenght": len(pkt),
            "ACK": 1 if (tcp_pkt.bits & 0x10) else 0,  # Flag ACK 
            "SYN": 1 if (tcp_pkt.bits & 0x02) else 0,  # Flag SYN 
        }
        if    features["Source"] in ipDict: features["Source"] = ipDict[features["Source"]]
        if    features["Destination"] in ipDict: features["Destination"] = ipDict[features["Destination"]]
        if    features["Protocol"] in protocolsDict: features["Protocol"] = protocolsDict[features["Protocol"]]
        #self.logger.info(features)
        features = np.array(list(features.values())).reshape(1, -1)

        # Predizione con il modello KMeans
        prediction = self.kmeans_model["kmeans_model"].predict(features)
        #self.logger.info(prediction)

        # Se la predizione appartiene al cluster maligno allora aggiorno i contatori e in caso superila soglia blocco l'IP
        if prediction[0] == 3:  
            self.counters[ip_pkt.src] += 1
            if self.counters[ip_pkt.src] > self.threshold:
                self.logger.warning(f"Pacchetto sospetto da {ip_pkt.src}, bloccato.")
                self._block_ip(datapath, ip_pkt.src)
                return
            
    def _udp_check(self, ip_pkt, pkt, datapath):
        """
            Estraggo dal pacchetto IP le caratteristiche rilevanti per il modello
        """
        features = {
            "No.": random.randint(1, 1000000),
            "Time": datetime.now().timestamp(),
            "Source": ip_pkt.src,
            "Destination": ip_pkt.dst,
            "Protocol": ip_pkt.proto,
            "Lenght": len(pkt),
            "ACK": 0,
            "SYN": 0
        }
        if    features["Source"] in ipDict: features["Source"] = ipDict[features["Source"]]
        if    features["Destination"] in ipDict: features["Destination"] = ipDict[features["Destination"]]
        if    features["Protocol"] in protocolsDict: features["Protocol"] = protocolsDict[features["Protocol"]]
        #self.logger.info(features)
        features = np.array(list(features.values())).reshape(1, -1)

        # Predizione con il modello KMeans
        prediction = self.kmeans_model["kmeans_model"].predict(features)
        self.logger.info(prediction)

        if prediction[0] == 3:  
            self.counters[ip_pkt.src] += 1
            if self.counters[ip_pkt.src] > self.threshold:
                self.logger.warning(f"Pacchetto sospetto da {ip_pkt.src}, bloccato.")
                self._block_ip(datapath, ip_pkt.src)
                return

    def _block_ip(self, datapath, ip_src):
        """
        Installa una flow entry che blocca tutto il traffico proveniente da un indirizzo IP sospetto.
        """
        parser = datapath.ofproto_parser
        # Crea un match per pacchetti IPv4 con sorgente uguale a ip_src
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src)
        actions = []  # Nessuna azione: i pacchetti verranno scartati
        # Installa la flow entry con priorità elevata timeout di 10 minuti
        self.add_flow(datapath, priority=1000, match=match, actions=actions, idle_timeout=600)

        # Crea un match per pacchetti TCP SYN con sorgente uguale a ip_src
        match2 = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_flags=0x02, ipv4_src=ip_src)  
        self.add_flow(datapath, priority=1000, match=match2, actions=actions, idle_timeout=600)

        self.logger.info("Bloccato traffico da IP %s su DPID %s", ip_src, datapath.id)
        
    def _reset_counters(self):
        """
        Thread che ogni 10 secondi resetta i contatori dei pacchetti SYN.
        """
        while True:
            hub.sleep(10)
            self.counters.clear()
            self.logger.info("Reset contatori.")
            
            # Richiede le statistiche per ogni datapath
            for datapath in self.datapaths.values():
                self.request_port_stats(datapath)

    def request_port_stats(self, datapath):
        """
        Richiede le statistiche delle porte allo switch specificato.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

