import vt
import requests
import json
###########################virustotal#################################################################################
def vts(ip):
    client = vt.Client("df5258471dd63dcd21c6490a2b3e096578ec9ddc00c01e4dc354a49098a2e2d1")
    url_id = vt.url_id(ip)

    urlr = client.get_object("/urls/{}", url_id)
    raw_result = urlr.last_analysis_stats
    malicious = str(raw_result['malicious'])
    harmless = str(raw_result['harmless'])
    #result = "Virustotal result is : " + malicious + " malicious " + harmless + ' harmless'
    return malicious, harmless

#######################################################################################################################
###########################abuseipdb#################################################################################

ip = '118.25.6.39'
def abip(ip):
    # Defining the api-endpoint
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': '3e9d1688f4e95345b71989173f0ae874c4827890148f54ef6c1437665acb95c7a3aee6520ceeb090'
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)

    # Formatted output
    decodedResponse = json.loads(response.text)
    result = json.dumps(decodedResponse, sort_keys=True, indent=4)
    abuseconfidence = decodedResponse['data']['abuseConfidenceScore']
    country = decodedResponse['data']['countryCode']
    totalreport = decodedResponse['data']['totalReports']
    iswhitelisted = decodedResponse['data']['isWhitelisted']
    domain = decodedResponse['data']['domain']
    return abuseconfidence, country, totalreport, iswhitelisted, domain

def res(ip):
    malicious, harmless = vts(ip)
    abuseconfidence, country, totalreport, iswhitelisted, domain = abip(ip)
    raw_result = f'''
    
    Virustotal scan : 
        harmless   =   {harmless}
        malicious  =   {malicious}
    
    AbuseIP scan    :
        abuse confidence   =   {abuseconfidence}
        country           =   {country}
        total report       =   {totalreport}
        is whitelisted     =   {iswhitelisted}
        domain            =   {domain}
        '''
    result = ''

    if int(malicious) > 2 and int(abuseconfidence) > 25:
        result = "This ip is malicious"
    else:
        result = "This  ip isn't malicious"

    return result,raw_result



