#!/usr/bin/python3
# ---------------------------
# (C) 2020 by Herby
#
# V 1.0

from Jumpscale import j
import time
import sys
import requests
import ipaddress


def get_my_reservations(tid):
    reservations = j.sal.zosv2.reservation_list(tid=tid,next_action="DEPLOY")
    return reservations


def check_public_ipv6(node):
    """
    check for public on any interface IPv6
    """

    ok = False
    for ii in node.ifaces:
        for ip in ii.addrs:
            ip = ip.split('/')[0]
            if ipaddress.ip_address(ip).version == 6:
                if ip[0] not in ['f',":"]:
                    ok = True

    return ok


def add_network_access(reservations,networkname):

    zos = j.sal.zosv2

    gwnodeid ='CBDY1Fu4CuxGpdU3zLL9QT5DGaRkxjpuJmzV6V5CBWg4'

    # retrieve existing network definition
    reservation=j.clients.explorer.explorer.reservations.get(9998)
    newreservation=j.clients.explorer.explorer.reservations.new()

    # retrieve existing network reservation
    n0 = reservation.data_reservation.networks[0]

    #add wg clients
    wg_config1 = zos.network.add_access(n0, gwnodeid , '10.11.211.0/24', ipv4=True)
    wg_config2 = zos.network.add_access(n0, gwnodeid , '10.11.212.0/24', ipv4=True)
    wg_config3 = zos.network.add_access(n0, gwnodeid , '10.11.213.0/24', ipv4=True)
    wg_config4 = zos.network.add_access(n0, gwnodeid , '10.11.214.0/24', ipv4=True)
    wg_config5 = zos.network.add_access(n0, gwnodeid , '10.11.215.0/24', ipv4=True)
    wg_config6 = zos.network.add_access(n0, gwnodeid , '10.11.216.0/24', ipv4=True)

    # copy network related part inside new reservation
    newreservation.data_reservation.networks.append(n0._ddict)

    print(wg_config1)
    print(wg_config2)
    print(wg_config3)
    print(wg_config4)
    print(wg_config5)
    print(wg_config6)

    # reapply the reservation
    rid = zos.reservation_register(newreservation, reservation.data_reservation.expiration_reservation, identity=me)
    result = zos.reservation_result(rid.reservation_id)
    print("provisioning result")
    print(result)


def get_free_ip(reservations,node,networkname):
    """
    find netork reservation
    and free IP on node for a specific network
    """
    ips=[]
    iprange=''
    for reservation in sorted(reservations, key=lambda r: r.id, reverse=True):
        if reservation.next_action != "DEPLOY":
            continue
        rnetworks = reservation.data_reservation.networks
        for network in rnetworks:
            if  network.name == networkname:
                for netres in network.network_resources:
                    if netres.node_id == node:
                        iprange = netres.iprange

        rcontainer = reservation.data_reservation.containers
        for container in rcontainer:
            if container.node_id == node:
                for netcon in container.network_connection:
                    if netcon.network_id == networkname:
                        ips.append(netcon.ipaddress)

        rkubernetes = reservation.data_reservation.kubernetes
        for kubernetes in rkubernetes:
            if kubernetes.node_id == node:
                ips.append(kubernetes.ipaddress)



    # asuming /24 !!
    if iprange == '':
        print("error: no network found for:",networkname)
        sys.exit(1)
    nodenet = iprange[0:-4]
    #search first free IP
    i = 1
    free_ip = ''
    
    while i<254:
        i+=1
        free_ip = nodenet+str(i)
        if free_ip not in ips:
            break
    # todo: check if free_ip is a valid IP
    return free_ip


def check_network_res(resid):
    '''
    check if networkres is Ok
    via results_k8s
    '''
    #todo loop

    res=j.clients.explorer.explorer.reservations.get(resid)
    results = j.sal.zosv2.reservation_result(res.id)
    print ("len:result:",len(results))
    res_nodes = []
    for r in results:
        res_nodes.append(r.node_id)

    nn = res.data_reservation.networks
    for n in nn:
        nr = n.network_resources
        print ("len:network_res:",len(nr))
        for r in nr:
            if r.node_id not in res_nodes:
                print (r.node_id, "missing")


def create_network():
    '''
    create a overlay network
    with all nodes from farms + GW inside
    !Attetione!
    can be a problem when more than 254 nodes --> IP Address logic
    '''

    # Load the zero-os sal and create empty reservation method
    zos = j.sal.zosv2
    r = zos.reservation_create()

    # change this
    expiration = int(j.data.time.HRDateToEpoch('2020/10/30'))
    
    overlay_network_ip_range = overlay_network_pre+"0.0/16"
    iprange = "automatic"

    # Farm ID of the farms involved
    #GEA_Salzburg1 = 12775
    #nodes_GEA_Salzburg1 = zos.nodes_finder.nodes_search(farm_id=GEA_Salzburg1)
    GEA_Vienna2 = 82872
    nodes_GEA_Vienna2 = zos.nodes_finder.nodes_search(farm_id=GEA_Vienna2)
	
    # Fixed IPv4 gateway node
    ipv4_gateway='CBDY1Fu4CuxGpdU3zLL9QT5DGaRkxjpuJmzV6V5CBWg4'
    gwnode = j.clients.explorer.explorer.nodes.get(ipv4_gateway)

    # Create network data structure
    network = zos.network.create(r, ip_range=overlay_network_ip_range, network_name=overlay_network_name)
    nodes_all = nodes_GEA_Vienna2
    nodes_all.append(gwnode)

    for i, node in enumerate(nodes_all):
        if (zos.nodes_finder.filter_is_up(node) and zos.nodes_finder.filter_is_free_to_use(node) and check_public_ipv6(node)):   # check for if you can pay with this token
            iprange = overlay_network_pre+f"{i+10}.0/24"
            zos.network.add_node(network, node.node_id , iprange)
            print("Node: ", i,node.farm_id, node.node_id,  " (",node.total_resources.cru, ") :", iprange)
        else:
            print("--> bad Node: ", i,node.farm_id, node.node_id,  " (",node.total_resources.cru, ") :", iprange, \
                zos.nodes_finder.filter_is_up(node),zos.nodes_finder.filter_is_free_to_use(node),check_public_ipv6(node))

    print("Node number: ", i, gwnode.node_id, ":", iprange,"  WG")

    wg_config1 = zos.network.add_access(network, gwnode.node_id, overlay_network_pre+'254.0/24', ipv4=True)
    wg_config2 = zos.network.add_access(network, gwnode.node_id, overlay_network_pre+'253.0/24', ipv4=True)
    wg_config3 = zos.network.add_access(network, gwnode.node_id, overlay_network_pre+'252.0/24', ipv4=True)
    wg_config4 = zos.network.add_access(network, gwnode.node_id, overlay_network_pre+'251.0/24', ipv4=True)

    print (80*"-")

    # print the wireguard config - store in a secure place.
    print("WG Interface configured:")
    print (80*"-")
    print(wg_config1)
    print (80*"-")
    print(wg_config2)
    print (80*"-")
    print(wg_config3)
    print (80*"-")
    print(wg_config4)
    print (80*"-")

    # register the reservation
    registered_reservation = zos.reservation_register(r, expiration, currencies=currency)

    print(registered_reservation)
    time.sleep(10)

    # inspect the result of the reservation provisioning
    result = zos.reservation_result(registered_reservation.reservation_id)
    print(result)

    time.sleep(10)
    check_network_res(registered_reservation.reservation_id)
    

def create_minio(nodeset):

    password = "perftest12345"  # zdb secret_set

    # customize this !!!
    zdb_size = 1024 # in GB !
    expiration = int(j.data.time.HRDateToEpoch('2020/10/30'))

    wallet = j.clients.stellar.get(wallet_name)

    flist_url = "https://hub.grid.tf/tf-official-apps/minio:latest.flist"

    zos = j.sal.zosv2
    reservation_zdbs = zos.reservation_create()
    reservation_storage = zos.reservation_create()

    if nodeset == "vie2":
        # vie2 cpu nodes
        """
		BvJzAiQTqTJoBZ1F5WzYoPpWUBoyRWp7agXSWnY7SBre
		HkfruwpT1yjx3TTiKn5PVBGFDmnTEqrzz6S36e4rFePb
		9LmpYPBhnrL9VrboNmycJoGfGDjuaMNGsGQKeqrUMSii
		3FPB4fPoxw8WMHsqdLHamfXAdUrcRwdZY7hxsFQt3odL
		CrgLXq3w2Pavr7XrVA7HweH6LJvLWnKPwUbttcNNgJX7
		9TeVx6vtivk65GGf7QSAfAuEPy5GBDJe3fByNmxt73eT
		Dv127zmU6aVkS8LFUMgvsptgReokzGj9pNwtz1ZLgcWf
		HXRB7qxBwMp1giM3fzRDRGYemSfTDiLUhteqtAvmWiBh
		GiSqnwbuvQagEiqMoexkq582asC8MattsjbFFuMdsaCz
		6mVGwQ41R9f7VJpNoJ6QLs4V15dsfMNXfEmQYhVEwCz6
        """
        minio_master_node_id = 'BvJzAiQTqTJoBZ1F5WzYoPpWUBoyRWp7agXSWnY7SBre'
        # vie2 apollo ########################################
        zdb_node_id=['4N6Rsb8QAMJXgcfWESDh1ccUkvjGWFrV4az65MZoLktb',
            '3yjVSkNM5vvpiQ8ey7xJHucHNrNvzkM5rWWASEYNsNQn',
            'DKxHM2qdSMw1c4s5bUdURWkmnvR9LiHP4cwTmCNZtpDK',
            'CayXiccrTd1uudPtBi1y6YusEXFFTENX3TShPJ85FnLJ',
            'CLbt5He2JibpLb4VQtBEeYz3r7j1YYopeNSGAtjZKPPQ']
        #this repeats the list of nodes 20 times. 
        #this was a mistake. 20x gets you 100 nodes (20x5). It should have been set to 4. But its not a showstopper
        zdb_node_id=20*zdb_node_id

    minio_master_node_ip = get_free_ip(myres,minio_master_node_id,overlay_network_name)

    print("minio_master_node_ip:",minio_master_node_ip)

    # Create volume for metadata storage
    volume = zos.volume.create(reservation_storage,minio_master_node_id,size=20,type='SSD')

    registered_reservation_volume = zos.reservation_register(reservation_storage, expiration, currencies=currency)

    # inspect the result of the reservation provisioning
    results_volume = zos.reservation_result(registered_reservation_volume.reservation_id)

    # make payment for the volume
    payment_id_volume=zos.billing.payout_farmers(wallet, registered_reservation_volume)

    for i, node_id in enumerate(zdb_node_id):
        zos.zdb.create(
            reservation=reservation_zdbs,
                node_id=node_id,
                size=zdb_size,
                mode='seq',
                password=password,
                disk_type="HDD",
                public=False)

    # register the reservation
    registered_reservation_zdbs = zos.reservation_register(reservation_zdbs, expiration, currencies=currency)

    # make payment for the zbds
    payment_id_zdb=zos.billing.payout_farmers(wallet, registered_reservation_zdbs)

    total_workloads = len(reservation_zdbs.data_reservation.zdbs) + len(reservation_zdbs.data_reservation.volumes)
    results_zdbs = zos.reservation_result(registered_reservation_zdbs.reservation_id)
    
    s=0
    
    while len(results_zdbs) < total_workloads:
        time.sleep(5)  # wait for worklaods to be deployed
        s += 5
        results_zdbs = zos.reservation_result(registered_reservation_zdbs.reservation_id)
        print ("\r","wait to finish zdbs... ",s, end = '')
    
    print("... zdbs created")
    
    # ----------------------------------------------------------------------------------
    # Read the IP address of the 0-db namespaces after they are deployed
    # we will need these IPs when creating the minio container
    # ----------------------------------------------------------------------------------
    namespace_config = []
    net = ipaddress.ip_network('200::/7')
    for result in results_zdbs:
        data = result.data_json
        valid_ip = None
        for address in data['IPs']:
            ip = ipaddress.ip_address(address)
            if ip not in net:
                valid_ip = address
                break

        if valid_ip == None:
            valid_ip = data['IPs'][0]
    
        cfg = f"{data['Namespace']}:{password}@[{valid_ip}]:{data['Port']}"
        namespace_config.append(cfg)

    # All IP's for the zdb's are now known and stored in the namespace_config structure.
    print(namespace_config)

    # ----------------------------------------------------------------------------------
    # With the low level disk managers done and the IP addresses discovered we can now build
    # the reservation for the min.io S3 interface.
    # ----------------------------------------------------------------------------------

    reservation_master_minio = zos.reservation_create()

    minio_secret_encrypted = j.sal.zosv2.container.encrypt_secret(minio_master_node_id, "perftest12345")

    shards_encrypted = j.sal.zosv2.container.encrypt_secret(minio_master_node_id, ",".join(namespace_config))
    secret_env = {"SHARDS": shards_encrypted, "SECRET_KEY": minio_secret_encrypted}

    minio_master_container=zos.container.create(
        reservation=reservation_master_minio,
        node_id=minio_master_node_id,
        network_name=overlay_network_name,
        ip_address=minio_master_node_ip,
        flist=flist_url,
        interactive=False,
        entrypoint= '',     #'/bin/entrypoint',
        cpu=4,
        memory=4096,
        public_ipv6=True,
        env={
            "DATA":"16",
            "PARITY":"4",
            "ACCESS_KEY":"perftest",
            "SSH_KEY": PUBKEY
            },
        secret_env=secret_env,
    )

    # ----------------------------------------------------------------------------------
    # Attach persistent storage to container - for storing metadata
    # ----------------------------------------------------------------------------------
    zos.volume.attach_existing(
        container=minio_master_container,
        volume_id=f'{registered_reservation_volume.reservation_id}-{volume.workload_id}',
        mount_point='/data')
    registered_reservation_minio_master = zos.reservation_register(reservation_master_minio, expiration, currencies=currency)
    results_master_minio = zos.reservation_result(registered_reservation_minio_master.reservation_id)

    # make payment for the minio_master
    payment_id_master_minio=zos.billing.payout_farmers(wallet, registered_reservation_minio_master)
    print ("Minio ID:",registered_reservation_minio_master.reservation_id)


def create_container(interact):

    HUB_URL = "https://hub.grid.tf/tf-bootable"
    wallet = j.clients.stellar.get(wallet_name)
    expiration = int(j.data.time.HRDateToEpoch('2020/12/31'))

    container_flist = f"{HUB_URL}/ubuntu:18.04-r1.flist"

    storage_url = "zdb://hub.grid.tf:9900"

    # node on which the container should run
    node_id="3h4TKp11bNWjb2UemgrVwayuPnYcs2M1bccXvi3jPR2Y"

    ip_address = get_free_ip(myres,node_id,overlay_network_name)

    node = j.clients.explorer.explorer.nodes.get(node_id)
    farm = j.clients.explorer.explorer.farms.get(node.farm_id)

    print ("--------  create container ---------")
    print ("IP:",ip_address)
    print ("node:",node_id)
    print ("Farm ID:",node.farm_id)
    print ("Farm Name:",farm.name)

    if interact == "YES":
        interactive = True
    else:
        interactive = False

    cpu = 1
    memory = 2048
    disk_size = 200*1024  # in MB !

    var_dict = {"pub_key": PUBKEY}
    entry_point = "/bin/bash /start.sh"

    # reservation structure initialisation
    zos = j.sal.zosv2

    reservation_container = j.sal.zosv2.reservation_create()

    container=zos.container.create(
        reservation=reservation_container,
        node_id=node_id,
        network_name=overlay_network_name,
        ip_address=ip_address,
        flist=container_flist,
        storage_url=storage_url,
        disk_size=disk_size,
        env=var_dict,
        public_ipv6=True,
        interactive=interactive,
        entrypoint=entry_point,
        cpu=cpu,
        memory=memory,)

    registered_reservation = zos.reservation_register(reservation_container, expiration, currencies=currency)

    payment_container=zos.billing.payout_farmers(wallet, registered_reservation)

    #print (registered_reservation,results_container,payment_container)
    print ("Reservation:",registered_reservation.reservation_id)
    time.sleep(5)
    result = zos.reservation_result(registered_reservation.reservation_id)
    s=5
    while (len(result) == 0) and (s < 120):
        time.sleep(5)  # wait for worklaods to be deployed
        s += 1
        result = zos.reservation_result(registered_reservation.reservation_id)
        print ("\r","wait to finish container... ",s, end = '')

    r0 = result[0]
    print("\r","IPv6:",r0.data_json['ipv6'])
    print("state:",r0.state)
    print("MSG:",r0.message)
    print ("--------  create container ---------")


def create_k8s():
    wallet = j.clients.stellar.get(wallet_name)
    expiration = int(j.data.time.HRDateToEpoch('2020/12/30'))

    zos = j.sal.zosv2

    # custiomize this
    cluster_secret = 'qqqqqqqqqq'
    size = 2

    res_k8s = zos.reservation_create()

    #sbg1
    node_master ='FCxp4JG2kr76dCnc2FzniApdwBak52uaSfbuigknS5Jx'
    node_workers=['FhfqdPSbEncHPWF74eDyDKjXTUfQjxwon9Hih9pG3Kjs',
        '7fHSAHEvUGtUcYSqLtpGq8ANssPikTyyHC52FddDYF4Y',
        'FjwyHVvfATkVb4Puh4x6jCMS79TVVgSYagAuZTxWrsbj',
        '9211BFV7MFwktD2b8jHE9Ub3fHRtaYQyBBfwT9kEKA7q',
        'FUq4Sz7CdafZYV2qJmTe3Rs4U4fxtJFcnV6mPNgGbmRg',
        '5Pb5NMBQWLTWhXK2cCM8nS6JZrnP2HaTP452TfMMYT9p']



    ip_master = get_free_ip(myres,node_master,overlay_network_name)
    ip_worker = []
    for wnode in node_workers:
        ip_worker.append(get_free_ip(myres,wnode,overlay_network_name))

    master = zos.kubernetes.add_master(
        reservation=res_k8s,           # reservation structure
        node_id=node_master,          # node_id to make the capacity reservation on and deploy the flist
        network_name=overlay_network_name,     # network_name deployed on the node (node can have multiple private networks)
        cluster_secret=cluster_secret,   # cluster pasword
        ip_address=ip_master,       # IP address the network range defined by network_name on the node
        size=size,            # 1 (1 logical core, 2GB of memory) or 2 (2 logical cores and 4GB of memory)
        ssh_keys=PUBKEY)

    print ("m:",master)
    worker = []
    for i, node in enumerate(node_workers):
        print ("worker:",i,node,)
        worker.append(zos.kubernetes.add_worker(
            reservation=res_k8s,
            node_id=node,
            network_name=overlay_network_name,
            cluster_secret=cluster_secret,
            ip_address=ip_worker[i],
            size=size,
            master_ip=ip_master,
            ssh_keys=PUBKEY))

    print ("w:",worker)
    registered_reservation = zos.reservation_register(res_k8s, expiration, currencies=currency)
    results_k8s = zos.reservation_result(registered_reservation.reservation_id)
    print("res:",results_k8s,registered_reservation.reservation_id)
    payment_k8s=zos.billing.payout_farmers(wallet, registered_reservation)
    print ("pay:",payment_k8s)

    #todo: check and wait for ready


#----------------------------------------------------------------------------------------------------------------------------



j.clients.explorer.default_addr_set('explorer.grid.tf')

# customize this
HERBERT = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCCoY7+AchsnObo1Qct15MZWZA7KgqCaxi3DSZM34zak0dttNn7UasQtHa86dcyLJ1LWe94CaRLhM/Yi9VwvNC5QlpMizygEyvaD4pKPsQjLFm0Gi8F1SxENtxL3rOOzqqDDrnASrEKYR8ULSBSC/VjdTE5CVOTGdxMJGDsPsT2VngWikMes9n/o9kfnjN5t2SkukP6SxsxbB34RQLkdTXDvbH3JnlsjbCvtmyIq4l/SrjikjMRUyOorzPBenxzl1Jm+Fj4FYpjq277o07fqF4iOBRZ7brn1fjPxB+e8vkZ4JYC5Dodp55QxF7881VSae+G/wd9eKk8WJDOztF59jJ hteibler@miix720"
JOE = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCugLxh3mQb/TNgnx/qdSHd8yeZnP/IPLWsuSHJ6mhYnasimHzI9BBlxmMwbdODFZQYV4A4PEEy7bAGLbK6GDzZdEM4qkC5yn/SfmrHg0DGAJroGEbZMC2aOv/fAdZzHLz0alGK7dl6OCPozs78Xa01rxEAEs4y0zI8HEIXtiI+ZSNNSn7FK0+LHfSAf+Nl9rlT3Qn2NiQ+loXWsHrnt524yP+KSt4/lllLH7a8kbdDQMilJdsYuBlof9FgZ7VDx4/8pKm7vEcP0vWGFsXb0e7FL8TAeMTorh7GuWdSjVeV59C2+ayHe3/94wjGLa9+ZKsXn8HcUjZNFwwoiE+9JFhjKxGWBzIrxSRL29TathO3Ds1YdG8cDaWSTvlBnhGhcSOwrpqzc4W/bm2OGdhOvWjKL7gZZ7zz1mrwrPafd0VaLtgxPqPUct+a6AmJv0ejKbp2Az7CJ5mMeAhBafxfWU4Y0/6Qq342LMNNLjtqciAQHCQrRikmDDF373m2myi/ph0= joefoxton@Joes-iMac.local"
GUIDO = "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAHYz5VlBX8wsp77sNwKOXTU4TaemZWdq290DTStVYflm2t3QrTeYrZEkS+JQCLFpQ0DpkcGqSr4ZVZ3h3igPg4FpQF9lo50kFLnmCZepWRQZDMpYnb8FvyNlz7YS9MiLKuqtPmb5m8KFOE2j35qdkNUxAbDyABnUjaisi3MZptkcA1iqA== gneum@R5-Mini"
AZMY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDQJpNHC/AWNRAuDkqAZH6Y6pJsafTT9kslY486v0Bt2PfVK12mGdzLblzneqKdL/c75XUC4ujxR/7RXdGV+bicMoFJDFJeXCGyglzq0ep86TSMnw8/17uLWHunxzHs3xMSAXVZnCHeOB9EMvkInn0SS6Bp6SfkVDcx1kVFoY4+UXI4+/OQDkzbP6BB1QUcexeyqknAhFFaB6xCoMajRSgwoGTbEmc2dIc3jT5FJyW4WxEUhbI3cFd/LmVwVp5ttEVoW7sWUEHcG6CFg6NUVOkcpQc0X7YuBJ7oNgZFSKyUiumQO54ABtmzSOovUal0/GCNblv9nka8sfyod5DAYofbPGNrqKHnDkJRk9dQeB2xuRNK2Uiyz/iw/f13qc7WXdPeYHUhz3HSsn6EX0+wWK+0Sbk5kdVd+Hl8T3Ra7O1e7p5JuAUjcYtrBdw1KE3JxXjnpH33ORKj9Y/obyVcbjvIrMTf0JjGoG76DQFS+j5dRlfVcf0Ldb194PsqYCbwAUs="

PUBKEY = JOE

#j.core.myenv.secret_set(secret="keines")
wallet_name='Green Edge Agent Wallet'
currency='TFTA'

me=j.me
tid = me.tid

overlay_network_name="perftest-vie2-1"
overlay_network_pre="10.23."  # / 16

## you only need to create the network once
#create_network()
#sys.exit()

print ("--> start get res:",time.strftime("%Y.%m.%d-%H:%M:%S"))
myres = get_my_reservations(tid)
print ("--> end   get res:",time.strftime("%Y.%m.%d-%H:%M:%S"))

# you can deploy now on this network resources, one by one
create_minio("vie2")
print ("--> finished:",time.strftime("%Y.%m.%d-%H:%M:%S"))
