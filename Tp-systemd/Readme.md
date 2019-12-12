# TP1-Systemd

# **I. `systemd`-basics**

## 1. First steps

 - s'assurer que `systemd` est PID
    >ps -ef
    UID          PID    PPID  C STIME TTY          TIME CMD
    root           1       0  0 11:32 ?        00:00:02 /usr/lib/systemd/systemd --switched-root

## 2. Gestion du temps

 - déterminer la différence entre Local Time, Universal Time et RTC time
	-   expliquer dans quels cas il peut être pertinent d'utiliser le RTC time

>timedatectl
               Local time: ven. 2019-11-29 12:32:35 CET
           Universal time: ven. 2019-11-29 11:32:35 UTC
                 RTC time: ven. 2019-11-29 11:32:36
                Time zone: Europe/Paris (CET, +0100)
System clock synchronized: yes
              NTP service: active
          RTC in local TZ: no

L'horloge RTC correspond à l'horloge matérielle , c'est l'horloge utilisé par le bios. L'horloge Local time est basé sur le fuseau horaire , cette dernière correspond à l'heure local de notre fuseau horaire, l'horloge Universal Time correspond à l'heure universelle se trouvant au centre de tous les fuseaux horaire.
Par défaut sous un OS contenant un kernel linux l'horloge RTC se base sur l'horloge Universal time. 

- timezones
  -  changer de timezone pour un autre fuseau horaire européen
>timedatectl set-timezone Europe/Andorra

>timedatectl
               Local time: ven. 2019-11-29 12:34:03 CET
           Universal time: ven. 2019-11-29 11:34:03 UTC
                 RTC time: ven. 2019-11-29 11:34:03
                Time zone: Europe/Andorra (CET, +0100)
System clock synchronized: yes
              NTP service: active
          RTC in local TZ: no

- on peut activer ou désactiver l'utilisation de la syncrhonisation NTP avec `timedatectl set-ntp <BOOLEAN>`
  -  désactiver le service lié à la synchronisation du temps avec cette commande, et vérifier à la main qu'il a été coupé

>timedatectl set-ntp 0
>timedatectl
               Local time: ven. 2019-11-29 12:37:38 CET
           Universal time: ven. 2019-11-29 11:37:38 UTC
                 RTC time: ven. 2019-11-29 11:37:39
                Time zone: Europe/Andorra (CET, +0100)
System clock synchronized: yes
              NTP service: inactive
          RTC in local TZ: no

## 3. Gestion de noms

  -  expliquer la différence entre les trois types de noms. Lequel est à utiliser pour des machines de prod ?

La commande `--static` permet de définir le hostname pour la machine au démarrage de façon manuel , la commande `--transit` permet de définir le hostname en le récupérant via les informations réseaux, la dernière commande `--pretty` est plus utilisée pour donner une description à un hôte.  La commande qui semble interessante à utiliser pour une machine de prod serait la `--static` afin d'avoir le nom que l'on souhaite, si un hostname est défini en `--static` alors la forme `--transit` n'est pas prise en compte.
>hostnamectl
   Static hostname: FedoraServer
         Icon name: computer-vm
           Chassis: vm
        Deployment: cours
        Machine ID: ce05818366a3460ab18011ae5d216d3e
           Boot ID: 426727397bff4cecb19d791fbabd1de1
    Virtualization: oracle
  Operating System: Fedora 31 (Server Edition)
       CPE OS Name: cpe:/o:fedoraproject:fedora:31
            Kernel: Linux 5.3.7-301.fc31.x86_64
      Architecture: x86-64

## 4. Gestion du réseau (et résolution de noms)

**NetworkManager**

 - afficher les informations DHCP récupérées par NetworkManager (sur une interface en DHCP)
 > nmcli con show enp0s3 | grep DHCP
DHCP4.OPTION[1]:                        dhcp_lease_time = 86400
DHCP4.OPTION[2]:                        dhcp_rebinding_time = 75600
DHCP4.OPTION[3]:                        dhcp_renewal_time = 43200
DHCP4.OPTION[4]:                        dhcp_server_identifier = 10.0.2.2
DHCP4.OPTION[5]:                        domain_name = auvence.co
DHCP4.OPTION[6]:                        domain_name_servers = 10.33.10.20 10.33.10.2 8.8.8.8 8.8.4.4
DHCP4.OPTION[7]:                        expiry = 1575110015
DHCP4.OPTION[8]:                        ip_address = 10.0.2.15
DHCP4.OPTION[9]:                        requested_broadcast_address = 1
DHCP4.OPTION[10]:                       requested_dhcp_server_identifier = 1
DHCP4.OPTION[11]:                       requested_domain_name = 1
DHCP4.OPTION[12]:                       requested_domain_name_servers = 1
DHCP4.OPTION[13]:                       requested_domain_search = 1
DHCP4.OPTION[14]:                       requested_host_name = 1
DHCP4.OPTION[15]:                       requested_interface_mtu = 1
DHCP4.OPTION[16]:                       requested_ms_classless_static_routes = 1
DHCP4.OPTION[17]:                       requested_nis_domain = 1
DHCP4.OPTION[18]:                       requested_nis_servers = 1
DHCP4.OPTION[19]:                       requested_ntp_servers = 1
DHCP4.OPTION[20]:                       requested_rfc3442_classless_static_routes = 1
DHCP4.OPTION[21]:                       requested_root_path = 1
DHCP4.OPTION[22]:                       requested_routers = 1
DHCP4.OPTION[23]:                       requested_static_routes = 1
DHCP4.OPTION[24]:                       requested_subnet_mask = 1
DHCP4.OPTION[25]:                       requested_time_offset = 1
DHCP4.OPTION[26]:                       requested_wpad = 1
DHCP4.OPTION[27]:                       routers = 10.0.2.2
DHCP4.OPTION[28]:                       subnet_mask = 255.255.255.0

**systemd-networkd**

 - stopper et désactiver le démarrage de `NetworkManager`
 >  sudo systemctl stop NetworkManager
 >  sudo systemctl disable NetworkManager
Removed /etc/systemd/system/multi-user.target.wants/NetworkManager.service.
Removed /etc/systemd/system/dbus-org.freedesktop.nm-dispatcher.service.
Removed /etc/systemd/system/network-online.target.wants/NetworkManager-wait-online.service.
 >   sudo systemctl status NetworkManager
● NetworkManager.service - Network Manager
   Loaded: loaded (/usr/lib/systemd/system/NetworkManager.service; disabled; vendor preset: >
   Active: inactive (dead)
     Docs: man:NetworkManager(8)
 - démarrer et activer le démarrage de `systemd-networkd`
> systemctl start systemd-networkd
> systemctl enable systemd-networkd
> Created symlink /etc/systemd/system/dbus-org.freedesktop.network1.service → /usr/lib/systemd/system/systemd-networkd.service.
Created symlink /etc/systemd/system/multi-user.target.wants/systemd-networkd.service → /usr/lib/systemd/system/systemd-networkd.service.
Created symlink /etc/systemd/system/sockets.target.wants/systemd-networkd.socket → /usr/lib/systemd/system/systemd-networkd.socket.
Created symlink /etc/systemd/system/network-online.target.wants/systemd-networkd-wait-online.service → /usr/lib/systemd/system/systemd-networkd-wait-online.service.

>sudo systemctl status systemd-networkd
● systemd-networkd.service - Network Service
   Loaded: loaded (/usr/lib/systemd/system/systemd-networkd.service; enabled; vendor preset:>
   Active: active (running) since Fri 2019-11-29 14:36:49 CET; 2min 7s ago
     Docs: man:systemd-networkd.service(8)
 Main PID: 1495 (systemd-network)
   Status: "Processing requests..."
    Tasks: 1 (limit: 2337)
   Memory: 2.2M
   CGroup: /system.slice/systemd-networkd.service
           └─1495 /usr/lib/systemd/systemd-networkd

 - éditer la configuration d'une carte réseau de la VM avec un fichier `.network`

> sudo cat /etc/systemd/network/enp0s8.network
[Match]
Name=enp0s8
> 
> [Network] 
> DNS=8.8.8.8 
> Address=192.168.50.51/24


>ifconfig
>enp0s8: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.50.51  netmask 255.255.255.0  broadcast 192.168.50.255
        ether 08:00:27:76:86:2a  txqueuelen 1000  (Ethernet)
        RX packets 162  bytes 15859 (15.4 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 112  bytes 14329 (13.9 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

**systemd-resolved**

 - activer la résolution de noms par `systemd-resolved` en démarrant le service (maintenant et au boot)

>sudo systemctl status systemd-resolved
● systemd-resolved.service - Network Name Resolution
   Loaded: loaded (/usr/lib/systemd/system/systemd-resolved.service; enabled;>
   Active: active (running) since Fri 2019-11-29 15:21:10 CET; 2min 47s ago
     Docs: man:systemd-resolved.service(8)
           https://www.freedesktop.org/wiki/Software/systemd/resolved
           https://www.freedesktop.org/wiki/Software/systemd/writing-network->
           https://www.freedesktop.org/wiki/Software/systemd/writing-resolver>
 Main PID: 1013 (systemd-resolve)
   Status: "Processing requests..."
    Tasks: 1 (limit: 2337)
   Memory: 10.1M
   CGroup: /system.slice/systemd-resolved.service
           └─1013 /usr/lib/systemd/systemd-resolved

 - on peut utiliser `resolvectl` pour avoir des infos sur le serveur local
 > resolvectl
Global
       LLMNR setting: yes
MulticastDNS setting: yes
  DNSOverTLS setting: no
      DNSSEC setting: allow-downgrade
    DNSSEC supported: yes
  Current DNS Server: 10.33.10.20
         DNS Servers: 10.33.10.20
                      10.33.10.2
                      8.8.8.8
                      8.8.4.4
Fallback DNS Servers: 1.1.1.1
                      8.8.8.8
                      1.0.0.1
                      8.8.4.4
                      2606:4700:4700::1111
                      2001:4860:4860::8888
                      2606:4700:4700::1001
                      2001:4860:4860::8844
          DNS Domain: auvence.co
          DNSSEC NTA: 10.in-addr.arpa
 - effectuer une requête DNS avec `systemd-resolve`

> systemd-resolve google.fr
google.fr: 172.217.19.227                      -- link: enp0s3
    -- Information acquired via protocol DNS in 424.5ms.
    -- Data is authenticated: no

 - Afin d'activer de façon permanente ce serveur DNS, la bonne pratique est de remplacer `/etc/resolv.conf` par un lien symbolique pointant vers `/run/systemd/resolve/stub-resolv.conf`

>sudo ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

 - Modifier la configuration de `systemd-resolved`
   -   elle est dans `/etc/systemd/resolved.conf`
   -   ajouter les serveurs de votre choix
   -   vérifier la modification avec `resolvectl`

> resolvectl
Global
       LLMNR setting: yes
MulticastDNS setting: yes
  DNSOverTLS setting: no
      DNSSEC setting: allow-downgrade
    DNSSEC supported: yes
         DNS Servers: 192.168.50.1
Fallback DNS Servers: 1.1.1.1
                      8.8.8.8
                      1.0.0.1
                      8.8.4.4
                      2606:4700:4700::1111
                      2001:4860:4860::8888
                      2606:4700:4700::1001
                      2001:4860:4860::8844

- mise en place de DNS over TLS
  -   renseignez-vous sur les avantages de DNS over TLS
  -   effectuer une configuration globale (dans `/etc/systemd/resolved.conf`)
      -   compléter la clause `DNS` pour ajouter un serveur qui supporte le DNS over TLS (on peut en trouver des listes sur internet)
      -   utiliser la clause `DNSOverTLS` pour activer la fonctionnalité
          -   valeur `opportunistic` pour tester les résolutions à travers TLS, et fallback sur une résolution DNS classique en cas d'erreur
          -   valeur `yes` pour forcer les résolutions à travers TLS

>sudo tcpdump -n -i enp0s3
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on enp0s3, link-type EN10MB (Ethernet), capture size 262144 bytes
16:12:22.510211 IP 10.0.2.15.46056 > 8.8.8.8.domain-s: Flags [S], seq 42364573, win 64240, options [mss 1460,sackOK,TS val 2894524247 ecr 0,nop,wscale 7,tfo  cookiereq,nop,nop], length 0

On voit alors que la résolution ce fait avec le port "domain-s" qui correspond au port 843. Nous avons bien une résolution DNSoverTLS.
La résolution DNS over TLS permet un chiffrement des données ce qui permet de diminuer le risque de fuites de donnée.

 - activer l'utilisation de DNSSEC
>resolvectl query sigfail.verteiltesysteme.net
sigfail.verteiltesysteme.net: resolve call failed: DNSSEC validation failed: invalid

>resolvectl query sigok.verteiltesysteme.net
sigok.verteiltesysteme.net: 134.91.78.139      -- link: enp0s3
-- Information acquired via protocol DNS in 88.2ms.
-- Data is authenticated: yes

## 5. Gestion de sessions `logind`

>  loginctl
SESSION  UID USER  SEAT  TTY
      1 1000 yoann seat0 tty1
      3 1000 yoann       pts/0
2 sessions listed.

>loginctl kill-session 1

> loginctl
SESSION  UID USER  SEAT TTY
      3 1000 yoann      pts/0
1 sessions listed.

>loginctl show-session 3
Id=3
User=1000
Name=yoann
Timestamp=Fri 2019-11-29 15:02:30 CET
TimestampMonotonic=118406420
VTNr=0
TTY=pts/0
Remote=yes
RemoteHost=192.168.50.1
Service=sshd
Scope=session-3.scope
Leader=906
Audit=3
Type=tty
Class=user
Active=yes
State=active
IdleHint=no
IdleSinceHint=1575041264739006
IdleSinceHintMonotonic=5232454775
LockedHint=no

## 6. Gestion d'unité basique (services)

- trouver l'unité associée au processus `chronyd`
>ps -e -o pid,cmd,unit | grep chronyd
   1535 /usr/sbin/chronyd           chronyd.service



# **II. Boot et Logs**

 - générer un graphe de la séquence de boot
   -   `systemd-analyze plot > graphe.svg`
   -   très utile pour du débug
   -   déterminer le temps qu'a mis `sshd.service` à démarrer

> cat graphe.svg | grep sshd.service
  `<text class="left" x="2988.383" y="4694.000">sshd.service (152ms)</text>
`

Le service `sshd.service` a démarré en 152 ms.



# III. Mécanismes manipulés par systemd

## 1. cgroups

 - identifier le cgroup utilisé par votre session SSH
   -   identifier la RAM maximale à votre disposition (dans `/sys/fs/cgroup`)
> cat /proc/934/cgroup
11:blkio:/
10:hugetlb:/
9:cpuset:/
8:pids:/user.slice/user-1000.slice/session-3.scope
7:freezer:/
6:devices:/user.slice
5:perf_event:/
4:memory:/user.slice/user-1000.slice/session-3.scope
3:net_cls,net_prio:/
2:cpu,cpuacct:/
1:name=systemd:/user.slice/user-1000.slice/session-3.scope
0::/user.slice/user-1000.slice/session-3.scope

>cat /sys/fs/cgroup/memory/user.slice/user-1000.slice/session-3.scope/memory.max_usage_in_bytes
`7741440
`

 - modifier la RAM dédiée à votre session utilisateur
   -   `systemctl set-property <SLICE_NAME> MemoryMax=512M`
   -   vérifier le changement
       -   toujours dans `/sys/fs/cgroup`

>systemctl set-property user-1000.slice MemoryMax=512M
>cat /sys/fs/cgroup/memory/user.slice/user-1000.slice/session-3.scope/memory.stat | grep limit
`hierarchical_memory_limit 536870912
`

- la commande `systemctl set-property` génère des fichiers dans `/etc/systemd/system.control/`
  -    vérifier la création du fichier
  -   on peut supprimer ces fichiers pour annuler les changements

>ls /etc/systemd/system.control/user-1000.slice.d/
`50-MemoryMax.conf
`
>cat /etc/systemd/system.control/user-1000.slice.d/50-MemoryMax.conf
```
# This is a drop-in unit file extension, created via "systemctl set-property"
# or an equivalent operation. Do not edit.
[Slice]
MemoryMax=536870912
```
> sudo rm -f /etc/systemd/system.control/user-1000.slice.d/50-MemoryMax.conf


## 2. D-Bus

J'ai commencé à lire le cours et à essayer de faire cette partie mais je n'ai pas très bien compris comment interpréter les événements.




 

