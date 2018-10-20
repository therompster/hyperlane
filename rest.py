from flask import Flask, abort, jsonify
from flask_jwt import JWT, jwt_required, current_identity
from werkzeug.security import safe_str_cmp
import requests
import json as j
import time
import paramiko
import mysql.connector
import ipahttp
from mysql.connector import errorcode

class User(object):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

    def __str__(self):
        return "User(id='%s')" % self.id

users = [
    User(1, 'cloud-bolt', 'K@ngar0o1!00'),
    #User(2, 'user2', 'abcxyz'),
]

username_table = {u.username: u for u in users}
userid_table = {u.id: u for u in users}

def authenticate(username, password):
    user = username_table.get(username, None)
    if user and safe_str_cmp(user.password.encode('utf-8'), password.encode('utf-8')):
        return user

##WILL CHANGE AFTER SECURITY SCAN ##
def identity(payload):
    user_id = payload['identity']
    return userid_table.get(user_id, None)


app = Flask(__name__)

app.debug = True
app.config['SECRET_KEY'] = 'super-secret'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False
jwt = JWT(app, authenticate, identity)

@app.route('/protected')
@jwt_required()
def protected():
    return '%s' % current_identity

def bad_request(message):
    response = jsonify({'message': message})
    response.status_code = 400
    return response

###API BOX START REST SERVICE###
@app.route("/start_rest_service/<internal_ip>")
#@jwt_required()
def start_api_service(internal_ip):
  ssh = paramiko.SSHClient()
  k = paramiko.RSAKey.from_private_key_file('/tmp/cb_key_pair.pem')
  # OR k = paramiko.DSSKey.from_private_key_file(keyfilename)
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  ssh.connect(hostname=internal_ip, username='centos', pkey=k)
  #ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo screen -S api')
  #stdout = ssh_stdout.read()
  #stderr = ssh_stderr.read()
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo service firewalld stop && sudo systemctl disable firewalld')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo nohup python3.5 /opt/rest.py')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  ssh.close()
  #if stderr:## PUT ERROR ATCHING AND RETRY HERE  CHECK AFTER AND SEE IF ITS THERE
  #return stdout,stderr ##CHANGE THIS TO OUTPUT
  return stdout
  #return "SUCCESS"

###ADD TO HA PROXY###
@app.route("/add_api_to_haproxy/<internal_ip>/<host_name>")
#@jwt_required()
def add_api_to_haproxy(internal_ip,host_name):
  ssh = paramiko.SSHClient()
  k = paramiko.RSAKey.from_private_key_file('/tmp/cb_key_pair.pem')
  # OR k = paramiko.DSSKey.from_private_key_file(keyfilename)
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  ssh.connect(hostname='172.18.0.27', username='centos', pkey=k)
  ftp = ssh.open_sftp()
  file=ftp.file('/etc/haproxy/haproxy.cfg', "a", -1)
  file.write(' server ' + host_name + ' ' + internal_ip +':5000 check port 5000\n')
  file.flush()
  ftp.close()
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo haproxy -f /etc/haproxy/haproxy.cfg -p /var/run/haproxy.pid -sf $(cat /var/run/haproxy.pid)')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  ssh.close()
##ADD TO FAILOVER HAPROXY
#  ssh.connect(hostname='172.18.0.32', username='centos', pkey=k)
# ftp = ssh.open_sftp()
#  file=ftp.file('/etc/haproxy/haproxy.cfg', "a", -1)
#  file.write(' server ' + host_name + ' ' + internal_ip +':5000 check port 5000\n')
#  file.flush()
#  ftp.close()
 # ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo haproxy -f /etc/haproxy/haproxy.cfg -p /var/run/haproxy.pid -sf $(cat /var/run/haproxy.pid)')
#  stdout = ssh_stdout.read()
#  stderr = ssh_stderr.read()
#  ssh.close()
  #if stderr:## PUT ERROR ATCHING AND RETRY HERE  CHECK AFTER AND SEE IF ITS THERE
  #return stdout,stderr ##CHANGE THIS TO OUTPUT
  return "SUCCESS"


###ADD TO HA PROXY###
@app.route("/add_api_to_jboss_haproxy/<internal_ip>/<host_name>")
#@jwt_required()
def add_jboss_to_haproxy(internal_ip,host_name):
  ssh = paramiko.SSHClient()
  k = paramiko.RSAKey.from_private_key_file('/tmp/cb_key_pair.pem')
  # OR k = paramiko.DSSKey.from_private_key_file(keyfilename)
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  ssh.connect(hostname='172.18.0.24', username='centos', pkey=k)
  ftp = ssh.open_sftp()
  file=ftp.file('/etc/haproxy/haproxy.cfg', "a", -1)
  file.write(' server ' + host_name + ' ' + internal_ip +':8080 check port 8080\n')
  file.flush()
  ftp.close()
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo haproxy -f /etc/haproxy/haproxy.cfg -p /var/run/haproxy.pid -sf $(cat /var/run/haproxy.pid)')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  ssh.close()
##ADD TO FAILOVER HAPROXY
#  ssh.connect(hostname='172.18.0.32', username='centos', pkey=k)
# ftp = ssh.open_sftp()
#  file=ftp.file('/etc/haproxy/haproxy.cfg', "a", -1)
#  file.write(' server ' + host_name + ' ' + internal_ip +':5000 check port 5000\n')
#  file.flush()
#  ftp.close()
 # ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo haproxy -f /etc/haproxy/haproxy.cfg -p /var/run/haproxy.pid -sf $(cat /var/run/haproxy.pid)')
#  stdout = ssh_stdout.read()
#  stderr = ssh_stderr.read()
#  ssh.close()
  #if stderr:## PUT ERROR ATCHING AND RETRY HERE  CHECK AFTER AND SEE IF ITS THERE
  #return stdout,stderr ##CHANGE THIS TO OUTPUT
  return "SUCCESS"




###FOR OPENSTACK USE ONLY BECAUSE OF FLOATING IP ISSUE ##
@app.route("/add_to_idm/<ip_address_uuid>/<hostname>/<internal_ip>")
#@jwt_required()
def add_to_idm(ip_address_uuid,hostname,internal_ip):
  floating_ip = get_floating_ip_from_id(ip_address_uuid)
  ssh = paramiko.SSHClient()
  k = paramiko.RSAKey.from_private_key_file('/tmp/cb_key_pair.pem')
  # OR k = paramiko.DSSKey.from_private_key_file(keyfilename)
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  ssh.connect(hostname=internal_ip, username='centos', pkey=k)
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo yum install ipa-client -y')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo mkdir -p /home/nfs-home && sudo chmod 777 /home/nfs-home')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo ipa-client-install --ip-address='+floating_ip+' --hostname=' + hostname + ' --server=itw-idm-1.itw.uspto.gov --domain=itw.uspto.gov -N --mkhomedir --unattended -p ipaadd@ITW.USPTO.GOV -w "(4OO2>P1Hy!0"')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  ssh.close()
  #if stderr:## PUT ERROR ATCHING AND RETRY HERE  CHECK AFTER AND SEE IF ITS THERE
  #return stdout,stderr ##CHANGE THIS TO OUTPUT
  return stdout
  #return "SUCCESS"

###FOR RHEL USE ONLY BECAUSE OF FLOATING IP ISSUE AND USERNAME ##
@app.route("/add_to_idm/rhel7/<ip_address_uuid>/<hostname>/<internal_ip>")
#@jwt_required()
def add_to_idm_rhel7(ip_address_uuid,hostname,internal_ip):
  floating_ip = get_floating_ip_from_id(ip_address_uuid)
  ssh = paramiko.SSHClient()
  k = paramiko.RSAKey.from_private_key_file('/tmp/cb_key_pair.pem')
  # OR k = paramiko.DSSKey.from_private_key_file(keyfilename)
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  ssh.connect(hostname=internal_ip, username='cloud-user', pkey=k)
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo yum install ipa-client -y')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  print(stderr)
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo mkdir -p /home/nfs-home')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  print(stderr)
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo ipa-client-install --ip-address='+floating_ip+' --hostname=' + hostname + ' --server=itw-idm-1.itw.uspto.gov --domain=itw.uspto.gov -N --mkhomedir --unattended -p ipaadd@ITW.USPTO.GOV -w "(4OO2>P1Hy!0"')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  print(stderr)
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo yum -y install katello-agent virt-who && service goferd start')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  ssh.close()
  #if stderr:## PUT ERROR ATCHING AND RETRY HERE  CHECK AFTER AND SEE IF ITS THERE
  #return stdout,stderr ##CHANGE THIS TO OUTPUT
  return stdout
  #return "SUCCESS"

###FOR RHEL USE ONLY BECAUSE OF FLOATING IP ISSUE AND USERNAME ##
@app.route("/remove_from_sat6/<ip_address>")
#@jwt_required()
def remove_from_sat6(ip_address):
  ssh = paramiko.SSHClient()
  k = paramiko.RSAKey.from_private_key_file('/tmp/cb_key_pair.pem')
  # OR k = paramiko.DSSKey.from_private_key_file(keyfilename)
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  ssh.connect(hostname=str(ip_address), username='cloud-user', pkey=k)
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo subscription-manager unregister')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  print(stderr)
  ssh.close()
  #if stderr:## PUT ERROR ATCHING AND RETRY HERE  CHECK AFTER AND SEE IF ITS THERE
  #return stdout,stderr ##CHANGE THIS TO OUTPUT
  #return stdout
  return "SUCCESS"

### IP ADDRESS CAN BE EITHER DNS NAME OR IP ADDRESS RHEL7 CLOUD IMAGE###
@app.route("/add_to_sat6/<ip_address>")
#@jwt_required()
def add_to_sat6(ip_address):
  ssh = paramiko.SSHClient()
  k = paramiko.RSAKey.from_private_key_file('/tmp/cb_key_pair.pem')
  # OR k = paramiko.DSSKey.from_private_key_file(keyfilename)
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  ssh.connect(hostname=str(ip_address), username='cloud-user', pkey=k)
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo rpm -Uvh http://sat6-pulp01.itw.uspto.gov/pub/katello-ca-consumer-latest.noarch.rpm')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  print(stderr)
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo subscription-manager register --org="USPTO" --activationkey="VDC_Key,1-rhel7"')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  print(stderr)
  print(stderr)
  ssh.close()
  #if stderr:## PUT ERROR ATCHING AND RETRY HERE  CHECK AFTER AND SEE IF ITS THERE
  #return stdout,stderr ##CHANGE THIS TO OUTPUT
  #return stdout
  return "SUCCESS"

### IP ADDRESS CAN BE EITHER DNS NAME OR IP ADDRESS RHEL7 CLOUD IMAGE###
@app.route("/add_to_sat5/<ip_address>")
#@jwt_required()
def add_to_sat5(ip_address):
  ssh = paramiko.SSHClient()
  k = paramiko.RSAKey.from_private_key_file('/tmp/cb_key_pair.pem')
  # OR k = paramiko.DSSKey.from_private_key_file(keyfilename)
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  ssh.connect(hostname=str(ip_address), username='cloud-user', pkey=k)
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo cd /usr/share/rhn/ && sudo wget http://itw-sat.etc.uspto.gov/pub/RHN-ORG-TRUSTED-SSL-CERT && sudo rpm -Uvh http://itw-sat.etc.uspto.gov/pub/rhn-org-trusted-ssl-cert-1.0-1.noarch.rpm')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo rhnreg_ks --activationkey "1-virtual_rhel7x,1-default_rhel7x" --serverUrl "https://itw-sat.etc.uspto.gov/XMLRPC"')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  print(stderr)
  ssh.close()
  #if stderr:## PUT ERROR ATCHING AND RETRY HERE  CHECK AFTER AND SEE IF ITS THERE
  #return stdout,stderr ##CHANGE THIS TO OUTPUT
  #return stdout
  return "SUCCESS"

### IP ADDRESS CAN BE EITHER DNS NAME OR IP ADDRESS RHEL7 CLOUD IMAGE###
@app.route("/import_sat5_GPG_key/<ip_address>")
#@jwt_required()
def import_sat5_GPG_key(ip_address):
  ssh = paramiko.SSHClient()
  k = paramiko.RSAKey.from_private_key_file('/tmp/cb_key_pair.pem')
  # OR k = paramiko.DSSKey.from_private_key_file(keyfilename)
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  ssh.connect(hostname=str(ip_address), username='cloud-user', pkey=k)
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo rpm --import http://itw-sat.etc.uspto.gov/pub/RPM-GPG-KEY-EPEL-7 && sudo rpm --import http://itw-sat.etc.uspto.gov/pub/GPG-KEY-USSS-USPTO')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  print(stderr)
  ssh.close()
  #if stderr:## PUT ERROR ATCHING AND RETRY HERE  CHECK AFTER AND SEE IF ITS THERE
  #return stdout,stderr ##CHANGE THIS TO OUTPUT
  #return stdout
  return "SUCCESS"

### IP ADDRESS CAN BE EITHER DNS NAME OR IP ADDRESS RHEL7 CLOUD IMAGE###
@app.route("/install_puppet_35/<ip_address>")
#@jwt_required()
def install_puppet_35(ip_address):
  ssh = paramiko.SSHClient()
  k = paramiko.RSAKey.from_private_key_file('/tmp/cb_key_pair.pem')
  # OR k = paramiko.DSSKey.from_private_key_file(keyfilename)
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  ssh.connect(hostname=str(ip_address), username='cloud-user', pkey=k)

  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo yum -y remove puppet && sudo rm -rf /var/lib/puppet/ssl')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()

  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo yum -y --disablerepo=* --enablerepo=puppet3.3-el7-x86_64 install puppet')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  print(stderr)

  ftp=ssh.open_sftp()
  ftp.put('/opt/puppet/puppet.conf','/home/cloud-user/puppet.conf')
  ftp.close()
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo mv /home/cloud-user/puppet.conf /etc/puppet/puppet.conf')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo puppet agent -t')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  ssh.close()
  print(stdout)
  #if stderr:## PUT ERROR ATCHING AND RETRY HERE  CHECK AFTER AND SEE IF ITS THERE
  #return stdout,stderr ##CHANGE THIS TO OUTPUT
  #return stdout
  return "SUCCESS"

#@app.route("/get_floating_ip_from_id/<float_uuid>")
def get_floating_ip_from_id(float_uuid):
  my_token = os_auth()
  url = "http://10.29.114.45:9696/v2.0/floatingips/"+float_uuid

  headers = {'Content-type': 'application/json', 'X-Auth-Token': my_token}
  r = requests.get(url, headers=headers)
  response = r.content
  json = j.loads(response.decode("utf-8"))
  ip = json['floatingip']['floating_ip_address']
  print(ip)
  return ip

@app.route("/remove_from_idm/<hostname>")
#@jwt_required()
def remove_from_idm(hostname):
  ipa = ipahttp.ipa('itw-idm-1.itw.uspto.gov')
  ipa.login('ipaadd@ITW.USPTO.GOV', '(4OO2>P1Hy!0')
  reply = ipa.host_del(hostname)
  error_code = j.dumps(reply['error'])
  #print("error" + j.dumps(reply['error']))
  #if error_code is None :
  #  return "SUCCESS"
  #else:
  #  return bad_request(str("ERROR REMOVING FROM IDM"))
  return "SUCCESS"


###AUTH FUNCTION FOR OPENSTACK###
def os_auth():
  url = "http://10.29.114.56:5000/v3/auth/tokens"
  data = {
      "auth": {
          "identity": {
              "methods": [
                  "password"
              ],
              "password": {
                  "user": {
                      "id": "cc06e6c4494e4c7287ed4dc6e6a0a804", # once service account for all of openstack is made it will go here
                      "password": "K@ngar0o1!00" ##once service account created this will be obfuscated
                  }
              }
          },
          "scope": {
              "project": {
                  "id": "5403ac818d0b4e0f94140e686b482994" ##once i get service account this will be changed to be brought in from POST
              }
          }
      }
  }
  headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
  try:
    r = requests.post(url, data=j.dumps(data), headers=headers)
    my_token = j.dumps(r.headers['X-Subject-Token'])
    my_token = my_token.replace('"', '')
  #except requests.exceptions.Timeout:
    # Maybe set up for a retry, or continue in a retry loop
  #except requests.exceptions.TooManyRedirects:
    # Tell the user their URL was bad and try a different one
  except requests.exceptions.RequestException as e:
    # catastrophic error. bail.
    print(e)
    ##Maybe EXIT ENTIRE APPLICATION sys.exit(1)
  return my_token
###END AUTH###


@app.route("/create_trove_instance")
#@jwt_required()
def trove_create():
  my_token = os_auth()
  url = "http://10.29.114.140:8779/v1.0/5403ac818d0b4e0f94140e686b482994/instances"
  data = {
      "instance": {
          "databases": [
              {
                  "character_set": "utf8",
                  "collate": "utf8_general_ci",
                  "name": "test_rami"
              }
          ],
          "flavorRef": "8c551377-a38c-4d4c-be92-555226036c20",
          "name": "test_rami",
          "users": [
              {
                  "databases": [
                      {
                          "name": "test_rami"
                      }
                  ],
                  "name": "rmansour",
                  "password": "rmansour"
              }
          ],
          "volume": {
              "size": 2
          },
          "datastore": {
              "version": "5.6",
              "type": "percona"
          }
      }
  }
  
  headers = {'Content-type': 'application/json', 'X-Auth-Token': my_token}
  r = requests.post(url, data=j.dumps(data), headers=headers)
  #print(r2)

  return str(r)
    
@app.route("/get_trove_ip")
#@jwt_required()
def trove_get_trove_ip():
  my_token = os_auth()
  url = "http://10.29.114.45:8774/v2.1/5403ac818d0b4e0f94140e686b482994/servers/detail?name=test_rami"
  
  headers = {'Content-type': 'application/json', 'X-Auth-Token': my_token}
  r = requests.get(url, headers=headers)
  response = r.content
  json = j.loads(response.decode("utf-8"))
  try:
    name = json['servers'][0]['name']
    ip = json['servers'][0]['addresses']['internal_portal_project'][0]['addr']
  except IndexError:
    name = "none found"
    ip = "Server Not Created Yet"
  #print(ip)
  return ip

## ADD FLOATING IP TO SERVER INSTANCE##
def os_associate_fip(internal_ip,floating_ip,vm_id):
  my_token = os_auth()
  url = "http://10.29.114.45:8774/v2.1/5403ac818d0b4e0f94140e686b482994/servers/" + vm_id + "/action"
  data = {
    "addFloatingIp" : {
      "address": floating_ip,
      "fixed_address": internal_ip
    }
  }

  headers = {'Content-type': 'application/json', 'X-Auth-Token': my_token}
  r = requests.post(url, data=j.dumps(data), headers=headers)
  #ADD CHECKS HERE FOR FLOATING IP ISSUES json_response = j.loads(r.text)
  return (r.text, r.status_code, r.headers.items())

##END ASSOCIATE FLOATING IP  CHANGE TO NEUTRON NEXT VERSION##
###CREATE OPENSTACK VM INSTANCE WITH VOLUME THAT DOES NOT DELETE###
@app.route("/create_os_vm/hostname/<hostname>/vol_size/<vol_size>")
#@jwt_required()
def os_vm_create(hostname,vol_size):
  my_token = os_auth()
  url = "http://10.29.114.45:8774/v2.1/5403ac818d0b4e0f94140e686b482994/servers"
  data = {
    "server": {
        "name": hostname,
        "flavorRef": "6654596b-84db-4f17-a185-596864dad5c4",
        "key_name": "cb_key_pair",
        "block_device_mapping_v2": [{
    	"boot_index": "0",
    	"uuid": "3ddd2a1d-aa0d-475c-b9a6-bac2458a21bf",
    	"source_type": "image",
    	"volume_size": vol_size,
    	"destination_type": "volume",
    	"delete_on_termination": "false",
    	"disk_bus": "virtio"}]
    }
  }

  headers = {'Content-type': 'application/json', 'X-Auth-Token': my_token}
  r = requests.post(url, data=j.dumps(data), headers=headers)
  json_response = j.loads(r.text)

  try:
    vm_id = json_response['server']['id']
    #time.sleep(20)
    r2 = get_os_vm_by_id(vm_id)
    r2_json = j.loads(r2.text)
    if r2_json['server']['status'] == "ACTIVE":
      print(r2_json['server']['addresses'][0]['addr'])
      return('good') 
    while r2_json['server']['status'] == "BUILD":
      r2 = get_os_vm_by_id(vm_id)
      r2_json = j.loads(r2.text)
      print(r2_json['server']['status'] + ' ' + vm_id)
      if r2_json['server']['status'] == "ERROR":
        return bad_request(str(r2_json['server']['fault']['message']))
      if r2_json['server']['status'] == "ACTIVE":
        #return bad_request(str(r2_json['server']['fault']['message']))
        ##DO AN ITERATION HERE FOR v1.2###
        vm_ip = r2_json['server']['addresses']['internal_portal_project'][0]['addr']
        ##HARD CODED FLOATING IP UNTIL NOT A POC ##
        os_associate_fip(vm_ip,'10.29.115.86',vm_id)
        return ('10.29.115.86')
    #return (r2.text, r2.status_code, r2.headers.items())
      #return (r2.text, r2.status_code, r2.headers.items())
  except KeyError as e:
    return (r.text, r.status_code, r.headers.items())
  except requests.exceptions.RequestException as e:
    return (r.text, r.status_code, r.headers.items())
  
#####################################

### GET OPENSTACK VM BY SERVER ID ###
@app.route("/get_os_vm_by_id/id/<id>")
#@jwt_required()
def get_os_vm_by_id(id):
  my_token = os_auth()
  url = "http://10.29.114.45:8774/v2.1/5403ac818d0b4e0f94140e686b482994/servers/" + id
  headers = {'Content-type': 'application/json', 'X-Auth-Token': my_token}
  r = requests.get(url, headers=headers)
  return (r)
#####################################


@app.route("/create_openshift_project/<project_name>")
#@jwt_required()
def create_project(project_name):
  ssh = paramiko.SSHClient()
  k = paramiko.RSAKey.from_private_key_file('/tmp/cb_key_pair.pem')
  # OR k = paramiko.DSSKey.from_private_key_file(keyfilename)
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  ssh.connect(hostname='172.18.0.29', username='centos', pkey=k)
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo oc login -u admin -p admin && sudo oc new-project ' + project_name)
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  ssh.close()
  config = {
          'raise_on_warnings': True,
          'failover' : [{
                  'user': 'root',
                  'password': 'k@ngar0o1!',
                  'host': '172.18.0.30',
                  'port': 3306,
                  'database': 'portal_api',
                  },
                  {
                  'user': 'root',
                  'password': 'k@ngar0o1!',
                  'host': '172.18.0.34',
                  'port': 3306,
                  'database': 'portal_api',
                  },
                  {
                  'user': 'root',
                  'password': 'k@ngar0o1!',
                  'host': '172.18.0.26',
                  'port': 3306,
                  'database': 'portal_api',
                  }]
  }
  conn = mysql.connector.connect(**config)
  cursor = conn.cursor()
  try:
    for result in cursor.execute("""INSERT INTO portal_api.events (id,deployment_id, func_id, input, output, error, status) VALUES (NULL,'0','8','sudo oc login -u admin -p admin;sudo oc new-project + project_name',%s,%s,1)""",(stdout,stderr),multi=True):
       if result.with_rows:
          print("rows producted by statement '{}':".format(result.statement))
          row = cursor.fetchone()
          while row:
             print(row)
             row = cursor.fetchone()
       else:
          print("Number of rows affeted by statement '{}':{}".format(result.statement, result.rowcount))
  except mysql.connector.Error as err:
          print(err.msg)
  conn.commit()
  conn.close()
  if stderr:
    return stdout,stderr ##CHANGE THIS TO OUTPUT
  if stdout:
    return stdout

## BEGIN MONGODB DEPLOYMENT for ROCKETCHAT OPENSHIFT
@app.route("/deploy_openshift_mongo-rocketchat")##Change to deploy_string later
#@jwt_required()
def deploy_mongo():
  ssh = paramiko.SSHClient()
  k = paramiko.RSAKey.from_private_key_file('/tmp/cb_key_pair.pem')
  # OR k = paramiko.DSSKey.from_private_key_file(keyfilename)
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  ssh.connect(hostname='172.18.0.29', username='centos', pkey=k)
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo oc new-app mongodb:latest -e MONGODB_ADMIN_PASSWORD=adminpassword -e MONGODB_USER=rocketchat -e MONGODB_PASSWORD=userpassword -e MONGODB_DATABASE=rocketchat')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  ssh.close()
  config = {
          'raise_on_warnings': True,
          'failover' : [{
                  'user': 'root',
                  'password': 'k@ngar0o1!',
                  'host': '172.18.0.30',
                  'port': 3306,
                  'database': 'portal_api',
                  },
                  {
                  'user': 'root',
                  'password': 'k@ngar0o1!',
                  'host': '172.18.0.34',
                  'port': 3306,
                  'database': 'portal_api',
                  },
                  {
                  'user': 'root',
                  'password': 'k@ngar0o1!',
                  'host': '172.18.0.26',
                  'port': 3306,
                  'database': 'portal_api',
                  }]
  }
  conn = mysql.connector.connect(**config)
  cursor = conn.cursor()
  try:
    for result in cursor.execute("""INSERT INTO portal_api.events (id,deployment_id, func_id, input, output, error, status) VALUES (NULL,'1','11','oc new-app mongo deployment',%s,%s,1)""",(stdout,stderr),multi=True):
       if result.with_rows:
          print("rows producted by statement '{}':".format(result.statement))
          row = cursor.fetchone()
          while row:
             print(row)
             row = cursor.fetchone()
       else:
          print("Number of rows affeted by statement '{}':{}".format(result.statement, result.rowcount))
  except mysql.connector.Error as err:
          print(err.msg)
  conn.commit()
  conn.close()
  if stderr:
    return stdout,stderr ##CHANGE THIS TO OUTPUT
  if stdout:
    return stdout

###DEPLOY ROCKETCHAT FRONT-END
@app.route("/deploy_openshift_rocketchat-web")##Change to deploy_string later
#@jwt_required()
def deploy_rocketchat():
  ssh = paramiko.SSHClient()
  k = paramiko.RSAKey.from_private_key_file('/tmp/cb_key_pair.pem')
  # OR k = paramiko.DSSKey.from_private_key_file(keyfilename)
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  ssh.connect(hostname='172.18.0.29', username='centos', pkey=k)
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo oc new-app rocketchat/rocket.chat:latest -e MONGO_URL=mongodb://rocketchat:userpassword@mongodb.rocketchat.svc:27017/rocketchat')
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  ssh.close()
  config = {
          'raise_on_warnings': True,
          'failover' : [{
                  'user': 'root',
                  'password': 'k@ngar0o1!',
                  'host': '172.18.0.30',
                  'port': 3306,
                  'database': 'portal_api',
                  },
                  {
                  'user': 'root',
                  'password': 'k@ngar0o1!',
                  'host': '172.18.0.34',
                  'port': 3306,
                  'database': 'portal_api',
                  },
                  {
                  'user': 'root',
                  'password': 'k@ngar0o1!',
                  'host': '172.18.0.26',
                  'port': 3306,
                  'database': 'portal_api',
                  }]
  }
  conn = mysql.connector.connect(**config)
  cursor = conn.cursor()
  try:
    for result in cursor.execute("""INSERT INTO portal_api.events (id,deployment_id, func_id, input, output, error, status) VALUES (NULL,'1','14','oc new-app rocketchat deployment',%s,%s,1)""",(stdout,stderr),multi=True):
       if result.with_rows:
          print("rows producted by statement '{}':".format(result.statement))
          row = cursor.fetchone()
          while row:
             print(row)
             row = cursor.fetchone()
             print(row)
             row = cursor.fetchone()
       else:
          print("Number of rows affeted by statement '{}':{}".format(result.statement, result.rowcount))
  except mysql.connector.Error as err:
          print(err.msg)
  conn.commit()
  conn.close()
  if stderr:
    return stdout,stderr ##CHANGE THIS TO OUTPUT
  if stdout:
    return stdout

##END ROCKET CHAT FRONTEND DEPLOYMENT

### BEGIN ROUTE CREATION FUNC
#####################################
###DEPLOY ROCKETCHAT FRONT-END
@app.route("/create_route-rocketchat/<hostname>")##Change to deploy_string later
#@jwt_required()
def create_route(hostname):
  ssh = paramiko.SSHClient()
  k = paramiko.RSAKey.from_private_key_file('/tmp/cb_key_pair.pem')
  # OR k = paramiko.DSSKey.from_private_key_file(keyfilename)
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  ssh.connect(hostname='172.18.0.29', username='centos', pkey=k)
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo oc expose svc/rocketchat --hostname=' + hostname)
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
  ssh.close()
  config = {
          'raise_on_warnings': True,
          'failover' : [{
                  'user': 'root',
                  'password': 'k@ngar0o1!',
                  'host': '172.18.0.30',
                  'port': 3306,
                  'database': 'portal_api',
                  },
                  {
                  'user': 'root',
                  'password': 'k@ngar0o1!',
                  'host': '172.18.0.34',
                  'port': 3306,
                  'database': 'portal_api',
                  },
                  {
                  'user': 'root',
                  'password': 'k@ngar0o1!',
                  'host': '172.18.0.26',
                  'port': 3306,
                  'database': 'portal_api',
                  }]
  }
  conn = mysql.connector.connect(**config)
  cursor = conn.cursor()
  try:
    for result in cursor.execute("""INSERT INTO portal_api.events (id,deployment_id, func_id, input, output, error, status) VALUES (NULL,'1','17','oc create/expose route + hostname',%s,%s,1)""",(stdout,stderr),multi=True):
       if result.with_rows:
          print("rows producted by statement '{}':".format(result.statement))
          row = cursor.fetchone()
          while row:
             print(row)
             row = cursor.fetchone()
             print(row)
             row = cursor.fetchone()
       else:
          print("Number of rows affeted by statement '{}':{}".format(result.statement, result.rowcount))
  except mysql.connector.Error as err:
          print(err.msg)
  conn.commit()
  conn.close()
  if stderr:
    return stdout,stderr ##CHANGE THIS TO OUTPUT
  if stdout:
    return stdout
## END ROUTE CREATION OPENSHIFT

########BEGINNING OF MANIFEST API#############

###PARSE JSON MANIFEST###
def parseManifest():
  json ='{"bundle_id":1,"instances":[{"deployment_type":1,"operating_system":1,"layer_id":1},{"deployment_type":1,"operating_system":1,"layer_id":1}]}' 

  p_json = j.loads(json)
  for builds in p_json['instances']:
  ##INSERT SERVICE DETAILS INTO DB HERE
    type_id = builds['deployment_type']
    os_id = builds['operating_system']
    layer_id = builds['layer_id']
    print("type : " + str(type_id) + " OS : " +str( os_id) + " layer_id : " + str(layer_id))

parseManifest();


##READ COMMANDS FROM DB ##
def get_commands(service_id):
  config = {
            'raise_on_warnings': True,
            'failover' : [{
                    'user': 'root',
                    'password': 'k@ngar0o1!',
                    'host': '172.18.0.30',
                    'port': 3306,
                    'database': 'manifest_intake',
                    },
                    {
                    'user': 'root',
                    'password': 'k@ngar0o1!',
                    'host': '172.18.0.34',
                    'port': 3306,
                    'database': 'manifest_intake',
                    },
                    {
                    'user': 'root',
                    'password': 'k@ngar0o1!',
                    'host': '172.18.0.26',
                    'port': 3306,
                    'database': 'manifest_intake',
                    }]
  }
  conn = mysql.connector.connect(**config)
  cursor = conn.cursor()
  sql = """SELECT type,cmd,local_path,remote_path FROM service_install_cmds WHERE service_id = %s"""
  cursor.execute(sql, (service_id,),multi=True)
  result = cursor.fetchall()
  return result
  conn.close()

def ssh_cmd(remote_command,remote_ip):
  ssh = paramiko.SSHClient()
  k = paramiko.RSAKey.from_private_key_file('/tmp/cb_key_pair.pem')
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  ssh.connect(hostname=str(remote_ip), username='centos', pkey=k)
##do foreach here from db commands
  ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('sudo ' + remote_command)
  stdout = ssh_stdout.read()
  stderr = ssh_stderr.read()
## store output and error here  
  return stdout,stderr

def cp_cmd(local_path,remote_path,remote_ip):
  ssh = paramiko.SSHClient()
  k = paramiko.RSAKey.from_private_key_file('/tmp/cb_key_pair.pem')
  ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  ssh.connect(hostname=str(remote_ip), username='centos', pkey=k)
  ftp=ssh.open_sftp()
  result = ftp.put(local_path ,remote_path)
  ftp.close()
  ssh.close()
#store result in db
  return result

def buildService(service_id,ip_address):
  commands = get_commands(service_id)
  for command in commands:
    if command[0] ==  "ssh_cmd":
      result = ssh_cmd(command[1],ip_address)
      print(result)
    if command[0] ==  "cp_cmd":
      result = cp_cmd(command[2],command[3],ip_address)

#buildService(1,'10.29.115.61')

app.run(host='0.0.0.0',threaded=True)
