import json
import uuid
import pandas as pd

dummyObj = {
    "UUID": "0",
    "frame.encap_type": "0",
    "frame.time_delta": "0",
    "frame.time_relative": "0",
    "frame.len": "0",
    "frame.cap_len": "0",
    "frame.marked": "0",
    "frame.ignored": "0",
    "frame.protocols": "0",
    "eth.type": "0",
    "ip.hdr_len": "0",
    "ip.dsfield": "0",
    "ip.dsfield.dscp": "0",
    "ip.dsfield.ecn": "0",
    "ip.flags": "0",
    "ip.flags.rb": "0",
    "ip.flags.df": "0",
    "ip.flags.mf": "0",
    "ip.frag_offset": "0",
    "ip.ttl": "0",
    "ip.proto": "0",
    "ip.checksum": "0",
    "ip.checksum.status": "0",
    "ipv6.tclass"
    "ipv6.tclass.dscp"
    "ipv6.tclass.ecn"
    "ipv6.flow"
    "ipv6.plen"
    "ipv6.hlim"
    "tcp.stream": "0",
    "tcp.len": "0",
    "tcp.flags.res": "0",
    "tcp.flags.ns": "0",
    "tcp.flags.cwr": "0",
    "tcp.flags.ecn": "0",
    "tcp.flags.urg": "0",
    "tcp.flags.ack": "0",
    "tcp.flags.push": "0",
    "tcp.flags.reset": "0",
    "tcp.flags.syn": "0",
    "tcp.flags.fin": "0",
    "tcp.completeness": "0",
    "tcp.completeness.rst": "0",
    "tcp.completeness.fin": "0",
    "tcp.completeness.data": "0",
    "tcp.completeness.ack": "0",
    "tcp.completeness.syn-ack": "0",
    "tcp.completeness.syn": "0",
    "tcp.completeness.str": "0",
    "tcp.window_size_value": "0",
    "tcp.window_size": "0",
    "tcp.window_size_scalefactor": "0",
    "tcp.checksum": "0",
    "tcp.checksum.status": "0",
    "tcp.urgent_pointer": "0",
    "tcp.options.nop": "0",
    "tcp.option_kind": "0",
    "tcp.analysis.initial_rtt": "0",
    "tcp.analysis.bytes_in_flight": "0",
    "tcp.analysis.push_bytes_sent": "0",
    "tls.record.content_type": "0",
    "tls.record.version": "0",
    "tls.record.length": "0",
    "dtls.record.content_type": "0",
    "dtls.record.version": "0",
    "dtls.record.length": "0",
    "dtls.handshake.type": "0",
    "dtls.handshake.length": "0",
    "udp.length": "0",
    "udp.checksum": "0",
    "udp.checksum.status": "0",
    "udp.stream": "0",
    "udp.time_relative": "0",
    "udp.time_delta": "0",
    "dns.flags.response": "0",
    "dns.flags.opcode": "0",
    "dns.flags.authoritative": "0",
    "dns.flags.truncated": "0",
    "dns.flags.recdesired": "0",
    "dns.flags.recavail": "0",
    "dns.flags.z": "0",
    "dns.flags.authenticated": "0",
    "dns.flags.checkdisable": "0",
    "dns.flags.rcode": "0",
    "dns.count.queries": "0",
    "dns.count.answers": "0",
    "dns.count.auth_rr": "0",
    "dns.count.add_rr": "0",
    "dns.qry.name.len": "0",
    "dns.count.labels": "0",
    "dns.qry.type": "0",
    "dns.qry.class": "0",
    "quic.packet_length": "0",
    "quic.header_form": "0",
    "quic.fixed_bit": "0",
    "quic.long.packet_type": "0",
    "quic.version": "0",
    "quic.length": "0",
    "_ws.expert.severity": "0",
    "_ws.expert.group": "0",
    "stun.type": "0",
    "stun.type.class": "0",
    "stun.type.method": "0",
    "stun.type.method-assignment": "0",
    "stun.length": "0",
    "stun.network_version": "0",
    "stun.attribute": "0",
    "stun.att.type": "0",
    "stun.att.length": "0",
    "stun.att.crc32": "0",
    "stun.att.crc32.status": "0",
    "alert": "0"
}

fields = list(dummyObj.keys())
dummyObj = {key.replace(".", "_"): value for key, value in dummyObj.items()}

def hexToInt(hex):
    return int(hex[2:], 16)

def findFieldValues(json_obj, search_fields):
    returnObj = dummyObj

    def searchRecursive(obj, search_fields):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key in search_fields:
                    if str(value).startswith("0x"):
                        returnObj[key.replace(".", "_")] = hexToInt(value)
                    elif key == "frame.protocols":
                        if "tcp" in str(value):
                            returnObj[key.replace(".", "_")] = "0"
                        elif "udp" in str(value):
                            returnObj[key.replace(".", "_")] = "1"
                    else:
                        returnObj[key.replace(".", "_")]=value
                elif isinstance(value, (dict, list)):
                    searchRecursive(value, search_fields)
        elif isinstance(obj, list):
            for item in obj:
                searchRecursive(item, search_fields)

    searchRecursive(json_obj, search_fields)
    returnObj["UUID"]=str(uuid.uuid4())
    return returnObj

def processData(data):
    insertData = []
    for obj in data:
        tmpObj = findFieldValues(obj, fields)
        insertData.append(tmpObj.copy())
    df = pd.DataFrame(insertData)
    df.to_csv('tmpData/benignData.csv', index=None)

# capture benign traffic
# sudo tshark -T json -i wlo1 -c 1000 -Y "not (ip.src == 192.168.1.28)" > benign.json 

with open ('tmpData/benign.json', 'r') as file:
    data = json.load(file)
    print("Processing " + str(len(data)) + " Packets")
    processData(data)



