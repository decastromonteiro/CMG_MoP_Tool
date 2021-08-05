import csv
import struct
import datetime


nat_start_path = r"C:\\Users\\ledecast\\Downloads\\cflowdV4_1\\cflow\\report\\cflowdreport_all_256_1.txt"
nat_end_path = r"C:\\Users\\ledecast\\Downloads\\cflowdV4_1\\cflow\\report\\cflowdreport_all_257_1.txt"

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

    return result

def main():
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
            row['flowStartMilliseconds'] = datetime.datetime.strptime(row['flowStartMilliseconds'], '%d/%m/%Y %I:%M:%S %p').strftime("%Y-%m-%d %H:%M:%S") # 2021-08-05 12:42:27
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
            row['flowEndMilliseconds'] = datetime.datetime.strptime(row['flowEndMilliseconds'], '%d/%m/%Y %I:%M:%S %p').strftime("%Y-%m-%d %H:%M:%S")
            nat_end.append(row)

    nat_flow = merge_nat_flows(nat_start, nat_end)


    with open("mergedNatflows.csv", "w") as fout:
        nat_flow.sort(key=lambda x: x['flowStartMilliseconds'])
        fieldnames = [key for key in nat_flow[0]]
        writer = csv.DictWriter(fout, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(nat_flow)


if __name__ == "__main__":
    main()
