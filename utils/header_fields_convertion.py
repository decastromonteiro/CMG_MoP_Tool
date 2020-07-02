# Referece
# imsi — UE IMSI
# imsi-2 — subscriber IMSI
# msisdn — UE MSISDN
# msisdn-without-cc — UE MSISDN without a country code
# subscriber-ip — UE IP address
# imei — subscriber IMEI
# rat-type — Radio Access Technology
# charging-id — subscriber charging ID
# charging-id-2 — subscriber charging ID
# pgw-ggsn-address — PGW/GGSN IP address serving the UE
# sgw-sgsn-address — SGW/SGSN IP address serving the UE
# sgw-sgsn-address-2 — SGW/SGSN IP address serving the UE
# apn — APN used by the UE
# apn-ni — APN-NI (Network Identifier) used by the UE
# timestamp — timestamp (inserted in Unix time format; for example: 1531204313)
# user-location — UE location (ULI)
# static-string — configured static string
# static-string-2 — configured static string
# billing-type — UE charging type
# roaming-status — subscriber’s roaming status
# plmn-id — Public Land Mobile Network (PLMN) ID of the SGSN/MME
# customer-id — Nokia customer ID
# imei-hyphenated — subscriber IMEI with format AABBBBBB-CCCCCC-EE
# imei-hyphenated-2 — subscriber IMEI with format AABBBBBB-CCCCCC-EE
# user-location-raw — ULI, in raw fmt <uli-type1>[+<uli-type2>]=<ULI hex>
# user-location-raw-2 — ULI, in raw fmt <uli-
# type1>[+<uli-type2>]=<ULI hex>

header_field_conversion = {
    'ip': 'subscriber-ip',
    'rat': 'rat-type',
    'location-info': 'user-location',
    'imeisv': 'imei'
}

cisco_to_cmg_he_conversion = {
    'bearer subscriber-ip-address': 'subscriber-ip',
    'bearer 3gpp imsi': 'imsi',
    'bearer radius-calling-station-id': 'msisdn',
    'bearer 3gpp sgsn-address': 'sgw-sgsn-address',
    'bearer 3gpp s-mcc-mnc': 'plmn-id',
    'bearer msisdn-no-cc': 'msisdn-without-cc',
    'bearer 3gpp imei': 'imei',
    # Workaround
    'string-constant N': 'static-string N',
    'string-constant TFWFM': 'static-string TFWFM',
    #
    'bearer 3gpp charging-id': 'charging-id',
    'bearer ggsn-address': 'pgw-ggsn-address',
    "bearer 3gpp uli": "user-location"


}

claro_cisco_field_dict = {

}
