import csv
import struct
import datetime
import ipaddress


encode_mapping = {
    'MSISDN': "!Q",
    'IMSI': "!Q",
    'IMEI': "!Q",
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


aa_flow_path = r"C:\\Users\\ledecast\\Downloads\\cflowdV4_1\\cflow\\report\\cflowdreport_all_13002_1.txt"

def convert_ipv6(hex_str):
    byte_str = bytes.fromhex(hex_str)
    ipv6 = ipaddress.ip_address(byte_str)
    if ipv6.ipv4_mapped:
        return str(ipv6.ipv4_mapped)
    return str(ipv6.compressed)

def main():

    with open(aa_flow_path) as csvf:
        aa_flow = []
        reader = csv.DictReader(csvf, delimiter='\t')
        for row in reader:
            row['sgsn'] = convert_ipv6(row['sgsn'])
            row['ggsn'] = convert_ipv6(row['ggsn'])
            row['msisdn'] = str(struct.unpack(encode_mapping.get('MSISDN'), bytes.fromhex(row['msisdn']))[0])
            row['imsi'] = str(struct.unpack(encode_mapping.get('IMSI'), bytes.fromhex(row['imsi']))[0])
            # row['imei'] = str(struct.unpack(encode_mapping.get('IMEI'), bytes.fromhex(row['imei']))[0])
            row['apn'] = bytes.fromhex(row['apn']).decode().rstrip("\x00")
            row["ratType"] = rat_type_map.get(row["ratType"].lstrip('0'))
            row['session_end_sec'] = datetime.datetime.utcfromtimestamp(float(int(row['session_end_sec'], 16))).strftime("%Y-%m-%d %H:%M:%S")
            row['session_start_sec'] = datetime.datetime.strptime(row['session_start_sec'], '%d/%m/%Y %I:%M:%S %p').strftime("%Y-%m-%d %H:%M:%S")

            row.pop(None, None)

            aa_flow.append(row)

    with open("parsedAAFlows.csv", "w") as fout:
        aa_flow.sort(key=lambda x: x['session_start_sec'])
        fieldnames = [key for key in aa_flow[0]]
        writer = csv.DictWriter(fout, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(aa_flow)

if __name__ == "__main__":
    main()
