import ipahttp

ipa = ipahttp.ipa('itw-idm-1.itw.uspto.gov')
ipa.login('ipaadd@ITW.USPTO.GOV', '(4OO2>P1Hy!0')
reply = ipa.host_find('rami')
for host in reply['result']['result']:
    print('Found host %s' % host['fqdn'][0])

