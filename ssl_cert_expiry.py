from tabulate import tabulate 
from pprint import pprint
from f5.bigip import ManagementRoot

mgmt = ManagementRoot('127.0.0.1', 'admin', 'admin')
ltm = mgmt.tm.ltm
sys= mgmt.tm.sys


results=[]

#get list of virtual servers 
virtuals = ltm.virtuals.get_collection()

for virtual in virtuals:
    client_ssl = None
    for profile in virtual.profiles_s.get_collection():
        if profile.context == "clientside":
                client_ssl = profile.name 
                results.append({"name":virtual.name,"destination":virtual.destination,"ssl_profile":client_ssl})


#obtain ssl profile  information from ltm profile

client_ssl_profiles=ltm.profile.client_ssls.get_collection()
ssl_certs= sys.file.ssl_certs.get_collection()

for result in results:
        if result['ssl_profile'] != None:
                for client_ssl_profile in client_ssl_profiles:
                        if client_ssl_profile.name ==result['ssl_profile']:
                                cert= client_ssl_profile.cert
                                result['cert']= client_ssl_profile.cert
                                
#extract ssl info from certificate mgmt 

                for ssl_cert in ssl_certs:
                        if result['cert'] == ssl_cert.fullPath:
                                result['expire']= ssl_cert.expirationString
                                result['subject']=ssl_cert.subject

print(tabulate(results,headers='keys'))




