import csv
import struct
import datetime
import ipaddress

nat_start_path = r"C:\\Users\\ledecast\\Downloads\\cflowdV4_1\\cflow\\report\\cflowdreport_192.168.1.183_53_1310722 (0_1_4_0_2)_256_1.txt"
nat_end_path = r"C:\\Users\\ledecast\\Downloads\\cflowdV4_1\\cflow\\report\\cflowdreport_192.168.1.183_53_1310722 (0_1_4_0_2)_257_1.txt"
aa_flow_path = r"C:\\Users\\ledecast\\Downloads\\cflowdV4_1\\cflow\\report\\cflowdreport_192.168.1.183_53_17956865 (1_1_2_0_1)_13002_1.txt"

encode_mapping = {
    'MSISDN': "!Q",
    'IMSI': "!Q",
    'IMEI': "!Q",
}

flow_end_reason = {
    "1": "Idle Timeout",
    "3": "End of Flow Detected",
    "4": "Forced End"
}


rat_type_map = {

"0": "Reserved",
"1": "UTRAN",
"2": "GERAN",
"3": "WLAN",
"4": "GAN",
"6": "EUTRAN",
"5": "HSPA-Evolution",
"7": "VIRTUAL",
"8": "EUTRAN_NB",
"9": "LTE_M",
"10": "NR",
"101": "IEEE-802-16e",
"102": "3GPP2-eHRPD",
"103": "3GPP2-HRPD",
"104": "3GPP2-1xRTT",
"10": "3GPP-EPS",

}

with open(nat_start_path) as csvf:
    nat_start = []
    reader = csv.DictReader(csvf, delimiter='\t')
    for row in reader:
        ue_ip = row.get('aluNatSubString').split("@")[1]
        row['ueIp'] = ue_ip
        row['MSISDN'] = str(struct.unpack(encode_mapping.get('MSISDN'), bytes.fromhex(row['MSISDN']))[0])
        row['IMSI'] = str(struct.unpack(encode_mapping.get('IMSI'), bytes.fromhex(row['IMSI']))[0])
        row['IMEI'] = str(struct.unpack(encode_mapping.get('IMEI'), bytes.fromhex(row['IMEI']))[0])
        row['APN'] = bytes.fromhex(row['APN']).decode().rstrip("\x00")
        row['flowStartMilliseconds'] = (datetime.datetime.strptime(row['flowStartMilliseconds'], '%d/%m/%Y %I:%M:%S %p') - datetime.datetime(1900,1,1)).total_seconds()
        nat_start.append(row)


with open(nat_end_path) as csvf:
    nat_end = []
    reader = csv.DictReader(csvf, delimiter='\t')
    for row in reader:
        ue_ip = row.get('aluNatSubString').split("@")[1]
        row['ueIp'] = ue_ip
        row['MSISDN'] = str(struct.unpack(encode_mapping.get('MSISDN'), bytes.fromhex(row['MSISDN']))[0])
        row['IMSI'] = str(struct.unpack(encode_mapping.get('IMSI'), bytes.fromhex(row['IMSI']))[0])
        row['IMEI'] = str(struct.unpack(encode_mapping.get('IMEI'), bytes.fromhex(row['IMEI']))[0])
        row['APN'] = bytes.fromhex(row['APN']).decode().rstrip("\x00")
        row['flowEndReason'] = flow_end_reason.get(row['flowEndReason'])
        row['flowEndMilliseconds'] = (datetime.datetime.strptime(row['flowEndMilliseconds'], '%d/%m/%Y %I:%M:%S %p') - datetime.datetime(1900,1,1)).total_seconds()
        nat_end.append(row)

def merge_nat_flows(nat_start, nat_end):
    nat_start_dict = {}
    for record in nat_start:
        key = record['flowId'] + record['postNATSourceIPv4Address'] + record['destinationIPv4Address'] + record['sourceTransportPort'] + record['postNAPTSourceTransportPort'] + record['destinationTransportPort'] + record['IMSI'] + record['APN'] + record['ueIp']
        nat_start_dict.update({
            key: record
        })
    
    nat_end_dict = {}

    for record in nat_end:
        key = record['flowId'] + record['postNATSourceIPv4Address'] + record['destinationIPv4Address'] + record['sourceTransportPort'] + record['postNAPTSourceTransportPort'] + record['destinationTransportPort'] + record['IMSI'] + record['APN'] + record['ueIp']
        nat_end_dict.update({
            key: record
        })

    result = []
    for key in nat_start_dict:
        if nat_end_dict.get(key):
            result.append(
                nat_start_dict.get(key) | nat_end_dict.get(key)
            )

    return result # LINEAR

def convert_ipv6(hex_str):
    byte_str = bytes.fromhex(hex_str)
    ipv6 = ipaddress.ip_address(byte_str)
    if ipv6.ipv4_mapped:
        return str(ipv6.ipv4_mapped)
    return str(ipv6.compressed)

def merge_aa_nat_flow(aa_flow, nat_flow):
    result = []
    mapped_flows = {}

    for aa_record in aa_flow:
        aa_key = aa_record['protocolIdentifier'] + aa_record['sourceTransportPort'] + aa_record['sourceIPv4Address'] + aa_record['destinationTransportPort'] + aa_record['destinationIPv4Address'] + aa_record['APN'] + aa_record['IMSI']
        if aa_key in mapped_flows:
            mapped_flows[aa_key]['AA'].append(aa_record)
        else:
            mapped_flows[aa_key] = {'AA': [aa_record]}

    for nat_record in nat_flow:
        nat_key = nat_record['protocolIdentifier'] + nat_record['sourceTransportPort'] + nat_record['ueIp'] + nat_record['destinationTransportPort'] + nat_record['destinationIPv4Address'] + nat_record['APN'] + nat_record['IMSI']
        if nat_key in mapped_flows:
            aa_dict = mapped_flows[nat_key]
            if aa_dict.get('NAT'):
                aa_dict['NAT'].append(nat_record)
            else:
                aa_dict['NAT'] = [nat_record]

    for record in mapped_flows:
        aa_len = len(mapped_flows[record].get('AA', []))
        nat_len = len(mapped_flows[record].get('NAT', []))

        if aa_len == 1 and nat_len:
            result.append(mapped_flows[record]['AA'][0] | mapped_flows[record]['NAT'][0])

        elif aa_len == nat_len:
            nat_record_list = mapped_flows[record]['NAT']
            for aa_record in mapped_flows[record]['AA']:
                check_min = None
                final_record = None
                for index, nat_record in enumerate(nat_record_list):
                    current_value = abs(aa_record['flowEndmsec'] - nat_record['flowEndMilliseconds'])
                    if check_min:
                        if current_value < check_min:
                            check_min = current_value
                            final_record = aa_record | nat_record
                            _index = index
                    else:
                        check_min = current_value
                        final_record = aa_record | nat_record
                        _index = index
                if final_record:
                    result.append(final_record)
                    del nat_record_list[_index]
        
        elif aa_len and (nat_len == 1) :
            for aa_record in mapped_flows[record]['AA']:
                result.append(aa_record | mapped_flows[record]['NAT'][0])

        else:
            print(f'There is no flow match between AA and NAT || AA Flows: {len(mapped_flows[record].get("AA", []))} || NAT Flows: {len(mapped_flows[record].get("NAT", []))}')



    return result

def main():
    

    with open(aa_flow_path) as csvf:
        aa_flow = []
        reader = csv.DictReader(csvf, delimiter='\t')
        for row in reader:
            row['sgw-sgsnAddr'] = convert_ipv6(row['sgw-sgsnAddr'])
            row['pgw-ggsnAddr'] = convert_ipv6(row['pgw-ggsnAddr'])
            row['MSISDN'] = str(struct.unpack(encode_mapping.get('MSISDN'), bytes.fromhex(row['MSISDN']))[0])
            row['IMSI'] = str(struct.unpack(encode_mapping.get('IMSI'), bytes.fromhex(row['IMSI']))[0])
            row['IMEI'] = str(struct.unpack(encode_mapping.get('IMEI'), bytes.fromhex(row['IMEI']))[0])
            row['APN'] = bytes.fromhex(row['APN']).decode().rstrip("\x00")
            row["ratType"] = rat_type_map.get(row["ratType"].lstrip('0'))
            row['aaChargingGrp'] = bytes.fromhex(row['aaChargingGrp']).decode().rstrip("\x00")
            row['session_start_sec'] = (datetime.datetime.strptime(row['session_start_sec'], '%d/%m/%Y %H:%M:%S') - datetime.datetime(1900,1,1)).total_seconds()
            row['flowEndmsec'] = (int(row['session_dur_msec']) / 1000) + row['session_start_sec']

            row.pop(None, None)

            aa_flow.append(row) # LINEAR

    nat_flow = merge_nat_flows(nat_start, nat_end)

    a = merge_aa_nat_flow(aa_flow, nat_flow)

    with open("cflowd_result.txt", "w") as fout:

        a = sorted(a, key= lambda x: x['flowStartMilliseconds'])

        for record in a:
            start_time_diff = record['session_start_sec'] - record['flowStartMilliseconds']
            end_time_diff = record['flowEndmsec'] - record['flowEndMilliseconds']
            if end_time_diff > 0:
                fout.write(f"Start Time Diff: {start_time_diff}\n")
                fout.write(f"End Diff: {end_time_diff}\n")
                fout.write(f"Flow End Reason: {record['flowEndReason']}\n")
                fout.write("\n\n")


    with open("cflowd_result.csv", "w") as fout:
        a = sorted(a, key= lambda x: x['flowStartMilliseconds'])
        fieldnames = [key for key in a[0]]
        writer = csv.DictWriter(fout, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(a)


if __name__ == "__main__":
    main()
