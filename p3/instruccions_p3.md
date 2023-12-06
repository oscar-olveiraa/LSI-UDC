# **Práctica 3 Legislación e Seguridad Informática**

> Este ano mandaronnos facer os exercicios 1,2,3,6,7.

### **1.-Tomando como base de trabajo el SSH pruebe sus diversas utilidades:**

> Para ver archivos ocultos de un directorio -> `ls -la`


A) Abra un shell remoto sobre SSH y analice el proceso que se realiza. Configure su fichero ssh_known_hosts para dar soporte a la clave pública del servidor.


   * **Analisis do proceso de conexion en ssh:**
  
      Para ver o proceso que se fai durante a conexion ssh -> `ssh -v lsi@x.x.x.x` 
   
      Podese poñer `ssh  lsi@x.x.x.x -v` e ademais podemos aumentar a informacion do proceso aumentando o nuemro de 'v', p.e `ssh -vvv lsi@x.x.x.x`)
   
   * **-Configuración archivo *ssh_known_hosts*:**

     1)Creamos o archivo *ssh_known_hosts* -> `touch /etc/ssh/ssh_known_hosts`

     2)Añadimos a salida do comando `ssh-keyscan` a ese archivo (ssh-keyscan é un comando para recopilar as claves públicas dos servidores SSH) -> `ssh-keyscan 10.11.49.118 >> /etc/ssh/ssh_known_hosts`

     3)Vaciamos o contido do archivo `known_hosts` do *.ssh* (archivo oculto de /home/lsi) -> `echo "" > /home/lsi/.ssh/known_hosts`

     Unha vez que seguimos os anteriores pasos, si facemos `ssh lsi@maquina_compi` non debería saltar a advertencia de fingerprinting (ocurre cando SSH non recoñece a clave pública do servidor ao que nos estamos conectando)

#
 
B) Haga una copia remota de un fichero utilizando un algoritmo de cifrado determinado. Analice el proceso que se realiza.

  > Cipher é un algortimo de cifrado simétrico e asimétricos que se utilizan para establecer unha conexión segura entre hosts

  Para ver os algoritmos de cifrado dispoñibles na máquina -> `ssh -Q cipher`

  Para ver a lista dos algoritmos que se aplican por defecto, facendo `ssh -vv lsi@x.x.x.x` veremos estas dúas lineas indicando os algoritmos por defecto:

      debug2:ciphers ctos: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
      debug2: ciphers stoc: chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com

      ---------
      ciphers ctos -> algoritmos cifrados que o cliente (ctos) está disposto a utilizar durante a negociación da conexión SSH
      ciphers stoc -> algoritmos cifrados que o servidor (stoc) acepta durante a negociación.

  Copia remota con un algoritmo cifrado -> `scp -c aes256-ctr archivo.txt lsi@10.11.48.118:/home/lsi/`  

#
  
C) Configure su cliente y servidor para permitir conexiones basadas en un esquema de autenticación de usuario de clave pública.

  > IMPORTANTE:
  >
  > -CREAR AL CLAVES COMO USUARIO LSI XA QUE INICIAMOS CONEXIÓN COMO USUARIO, NON COMO ROOT.
  >
  > -A CLAVE PRIVADA NON SE LLE DA NADIE, SOLO A PODEMOS TER NÓS, O ÚNICO QUE SE DAN SON CLAVES PÚBLICAS.
  >


  Para crear as claves -> lsi@debian:~$ `ssh-keygen -t rsa`

  O noso compañeiro mete a nosa clave pública na súa máquina para así cando fagamos un ssh á súa máquina non nos pida a súa contraseña (basicamente a clave pública é como si fora o candado e a clave privada é como si fora a chave, si temos o candado en esa máquina, como nos temos a chave podemos entrar): 

  1)Creamos unha carpeta en */home/lsi* para gardar temporalmete esa clave -> `mkdir clave`

  2)O noso compañeiro copia esa chave na carpeta temporal desde */home/lsi/.ssh*-> `scp lsi@10.11.48.135:/home/lsi/.ssh/*.pub ../clave`

  3)Creamos un archivo en */home/lsi/.ssh*-> `touch authorized_keys`

  4)Sobrescribimos ese archivo desde */home/lsi/.ssh* ca clave pública que esta na carpeta temporal -> `cat ../clave/id_rsa.pub >> authorized_keys`

  Comprobamos o funcionamento facendo un `ssh lsi@ip_compa` e mirar que non nos pida a súa contraseña.

#
  
D) Mediante túneles SSH securice algún servicio no seguro.

  Para crear o tunel ssh -> `ssh -L 9090:localhost:80 lsi@10.11.48.118 -N`

  Comprobación (o 'cliente' ten que estar escoitando mentres o servidor lle manda mensaxes):

  Quen estableza o tunel -> `echo "Hola desde mi máquina local" | nc -q 0 localhost 9090` (mirar o do -q)

  Quen estea como 'cliente', recibirá ese mensaxe cando estea escoitando -> `nc -l -p 8080`

  2º comprobación:

  Si o servidor fai `lynx http://127.0.0.1:9090` debería estar no apache do compañeiro

#
  
E) “Exporte” un directorio y “móntelo” de forma remota sobre un túnel SSH.

Montar o directorio remoto (en este caso /tmp/cositas) en un directorio local (/mnt/oscar_montura/)
```
sshfs lsi@10.11.48.135:/tmp/cositas /mnt/oscar_montura/ -o follow_symlinks
```
Desmontar montura:
```
fusermount -u /mnt/oscar_montura/
```

  F) PARA PLANTEAR DE FORMA TEÓRICA.: Securice su sevidor considerando que únicamente dará servicio ssh para sesiones de usuario desde determinadas IPs.



### **2.-Tomando como base de trabajo el servidor Apache2**
   
  A. Configure una Autoridad Certificadora en su equipo.

  B. Cree su propio certificado para ser firmado por la Autoridad Certificadora. Bueno, y fírmelo.
  
  C. Configure su Apache para que únicamente proporcione acceso a un determinado directorio del árbol web bajo la condición del uso de SSL. Considere que si su la clave privada está cifrada en el proceso de arranque su 
     máquina le solicitará la correspondiente frase de paso, pudiendo dejarla inalcanzable para su sesión ssh de trabajo.



### **3.-Tomando como base de trabajo el openVPN deberá configurar una VPN entre dos equipos virtuales del laboratorio que garanticen la confidencialidad entre sus comunicaciones.**

 > Instalamos openVPN -> `apt install openvpn`
 >
 > Si ao iniciar o VPN nos sale este error (ERROR: Cannot ioctl TUNSETIFF tun1: Device or resource busy (errno=16)), matamos ao proceso -> `killall openvpn`
 >
 > No noso caso 10.11.48.118 fai de server e 10.11.48.135 de cliente. 

   ### - Servidor VPN:

   1) Na carpeta */etc/openvpn/* creamos unha clave -> `openvpn --genkey --secret vpn.key`
   
   2) Damoslle os seguintes permisos -> `chmod 640 vpn.key`

   3) Cambiamos de propiedad á clave e pasa a ser de nobody(usuario que ten un nivel moi baixo de privilexios e axuda a reforzar a seguridade limitando o acceso a esos archivos a un usuario con privilexios mínimos) -> `chown nobody vpn.key`

   4) Pasamoslle esa clave ao noso compañeiro -> `scp vpn.key lsi@10.11.48.135:/home/lsi/`

   5) En /etc/openvpn creamos un archivo 'tunel.conf' e añadimos as seguintes lineas:

          local 10.11.48.118
          remote 10.11.48.135
          dev tun1
          port 6969
          comp-lzo
          user nobody
          ping 15
          ifconfig 172.110.0.1 172.110.0.2 #indica ifconfig ip-origen ip-destino
          secret /etc/openvpn/vpn.key
          cipher AES-256-CBC
   6) Iniciamos o VPN (ten que estar o cliente tamén configurado e ca vpn iniciada para que se estableza a conexión). Comando para inicialo -> `openvpn --config /etc/openvpn/tunel.conf`


  ### - Cliente VPN:

  1) Movemos a clave a */etc/openvpn* -> `root@debian:/home/lsi# mv vpn.key /etc/openvpn/`

  2) Damoslle permisos -> `chmod 640 vpn.key`

  3) Cambiamos de propietario a nobody -> `chown nobody vpn.key `

  4) Creamos tamén o archivo 'tune.conf' en */etc/openvpn* e configuramos da mesma maneira solo que cas ips ao revés que o servidor:

         local 10.11.48.135
         remote 10.11.48.118
         dev tun1
         port 6969
         comp-lzo
         user nobody
         ping 15
         ifconfig 172.110.0.2 172.110.0.1
         secret /etc/openvpn/vpn.key
         cipher AES-256-CBC

  5) Iniciamos o VPN -> `openvpn --config /etc/openvpn/tunel.conf`

### Conexión por SSH ca IP do VPN

  Podemos entrar por ssh á máquina do compañeiro ca súa ip do vpn. Para poder facer eso metemos a súa ip nos wrappers. Exemplo cos wrappers do cliente:

    #loopback e compañeiro
    sshd: 127.0.0.1, 10.11.48.118, 10.11.50.118, 172.110.0.1: spawn echo `/bin/date`\: intento conectar %a con %A [PERMITIDO] >> /home/lsi/allows/logssh

  Comprobamos tendo en un terminal o VPN correndo e en outro establecer conexión por ssh -> `ssh lsi@172.110.0.1`

      
### **6.-En este punto, cada máquina virtual será servidor y cliente de diversos servicios (NTP, syslog, ssh, web, etc.). Configure un “firewall stateful” de máquina adecuado a la situación actual de su máquina.**

> Acordarse de borrar na máquina todos os comentarios que estean nos seguintes scripts.

  Creamos un cron(servizo que permite a execución programada de tareas, comandos, scripts de forma automática) para que cada 10 minutos se resetee o firewall. Con esto si pasa algo co firewall e non temos acceso á máquina, reseteanse as reglas e volveríamos a poder entrar.

  1) Creamos o script que resetee as reglas de iptables(vamos a gardar en un log os restarts que se van facendo, acordarse de vacialo cada x tempo xa que pode chegar a ocupar moito):

            #!/bin/bash

            #IPv4
            iptables -P INPUT ACCEPT       # Permitirá o tráfico de entrada menos que haxa reglas específicas que o bloqueen.
            iptables -P OUTPUT ACCEPT      # Permitirá o tráfico de saída menos que haxa reglas específicas que o bloqueen.
            iptables -P FORWARD ACCEPT     # Permite o reenvío por defecto.
            iptables -F                    # Restablece as reglas a un estado inicial vacío.
            iptables -X                    # Borra todas as cadenas((agrupacions de reglas)) personalizadas definidas polo usuario na tabla de filtrado.
            iptables -t nat -F             # Borra todas as reglas da tabla de traducción de direccións de rede (NAT)

            #IPv6
            ip6tables -P INPUT ACCEPT      
            ip6tables -P OUTPUT ACCEPT     
            ip6tables -P FORWARD ACCEPT    
            ip6tables -F                   
            ip6tables -X                   
            ip6tables -t nat -F            

            /bin/echo "$(date): firewall reset" >> /var/log/fw_reset.log

   1) Metemos no cron o script. Abrimos o editor de cron con `crontab -e` e añadimos a seguinte linea ao final:

          */10 * * * * bash /home/lsi/restart_firewall.sh

          -----------------EXPLICACIÓN-----------------

          [*/10]: Este campo indica a frecuencia de execución en minutos. O asterisco significa "calquer valor" (da igual minuto 20 que 50), e /10 significa "cada 10".
                 Polo tanto, esta parte indica que o cron job se executará cada 10 minutos.
          [*]: Este campo indica a hora do día. Un asterisco significa "calquer valor" polo que significa calquer hora do día.
          [*]: Este campo indica o día do mes. Un asterisco significa "calquer valor"polo que significa calquer día do mes.
          [*]: Este campo indica o mes. Un asterisco significa "calquer valor" polo que significa cualquier mes.
          [*]: Este campo indica o día da semana. Un asterisco significa "calquer valor" polo que significa calquer día da semana.
          [bash /home/lsi/reset_firewall.sh]: comando que se executará. Executaremos o script que resetea o firewall (restart_firewall.sh).


  O señor firewall:

    #!/bin/sh

    ipCompa=10.11.48.118
    ip6Compa=2002:a0b:3076::1
    ipCompaVPN=172.110.0.1
    ipVPN_1=10.20.32.0/21
    ipVPN_2=10.30.8.0/21
    servidorDNS1=10.8.12.49
    servidorDNS2=10.8.12.50
    servidorDNS3=10.8.12.47
    debianRep1=151.101.194.132
    debianRep2=151.101.130.132
    debianRep3=151.101.66.132
    debianRep4=151.101.2.132
    debianRep5=151.101.134.132
    ipLocalhost=127.0.0.1
    ip6Localhost=::1

    iptables -F
    iptables -X
    iptables -t nat -F


    #--Politicas por defecto--
    
    iptables -P INPUT DROP
    iptables -P OUTPUT DROP
    iptables -P FORWARD DROP

    ip6tables -P INPUT DROP
    ip6tables -P OUTPUT DROP
    ip6tables -P FORWARD DROP


    #--Reglas para un firewall control de estado. Permiten o tráfico que está asociado con conexións xa establecidas--
     
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT


    #--Reglas para permitir tráfico de loopback--
   
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    ip6tables -A INPUT -i lo -j ACCEPT
    ip6tables -A OUTPUT -o lo -j ACCEPT


    #--Reglas para permitir o tráfico IPv6 desde ou hacia dirección ip do compa--

    iptables -A INPUT -s $ipCompa -p ipv6 -j ACCEPT
    iptables -A OUTPUT -d $ipCompa -p ipv6 -j ACCEPT


    #--Reglas para poder coenctarte por ssh--

    iptables -A INPUT -s $ipVPN_1,$ipVPN_2,$ipCompa,$ipCompaVPN -p TCP --dport 22 -m conntrack --ctstate NEW -j ACCEPT
    iptables -A OUTPUT -d $ipCompa,$ipCompaVPN -p TCP --dport 22 -m conntrack --ctstate NEW -j ACCEPT

    ip6tables -A INPUT -s $ip6Compa -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
    ip6tables -A OUTPUT -d $ip6Compa -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT


    iptables -A OUTPUT -d $servidorDNS1,$servidorDNS2,$servidorDNS3 -p UDP --dport 53 -m conntrack --ctstate NEW  -j ACCEPT

    iptables -A INPUT -s $ipCompa -p TCP --dport 514 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -d $ipCompa -p TCP --dport 514 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

    iptables -A INPUT -s $ipCompa -p UDP --dport 6969 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -d $ipCompa -p UDP --dport 6969 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

    iptables -A OUTPUT -s $ipCompa,$ipLocalhost -p UDP --dport 123 -m conntrack --ctstate NEW -j ACCEPT
    iptables -A OUTPUT -d $ipCompa,$ipLocalhost -p UDP --dport 123 -m conntrack --ctstate NEW -j ACCEPT

    iptables -A INPUT -s $ipCompa -p TCP --dport 80 -m conntrack --ctstate NEW -j ACCEPT
    iptables -A OUTPUT -d $ipCompa,$debianRep1,$debianRep2,$debianRep3,$debianRep4,$debianRep5 -p TCP --dport 80 -m conntrack --ctstate NEW -j ACCEPT

    iptables -A INPUT -s $ipCompa -p TCP --dport 443 -m conntrack --ctstate NEW -j ACCEPT
    iptables -A OUTPUT -d $ipCompa -p TCP --dport 443 -m conntrack --ctstate NEW -j ACCEPT

    iptables -A INPUT -s $ipCompa,$ipCompaVPN,$ipLocalhost -p ICMP -m conntrack --ctstate NEW -j ACCEPT
    iptables -A OUTPUT -d $ipCompa,$ipCompaVPN,$ipLocalhost -p ICMP -m conntrack --ctstate NEW -j ACCEPT

    ip6tables -A INPUT -s $ip6Compa,$ip6Localhost -p icmpv6 -m conntrack --ctstate NEW -j ACCEPT
    ip6tables -A OUTPUT -d $ip6Compa,$ip6Localhost -p icmpv6 -m conntrack --ctstate NEW -j ACCEPT

    iptables -A INPUT -p UDP -j REJECT --reject-with icmp-port-unreachable
    iptables -A INPUT -p TCP -j REJECT --reject-with tcp-reset
    iptables -A INPUT -p ICMP -j REJECT --reject-with icmp-port-unreachable

    ip6tables -A INPUT -p udp -j REJECT --reject-with icmp6-port-unreachable
    ip6tables -A INPUT -p tcp -j REJECT --reject-with tcp-reset
    ip6tables -A INPUT -p icmpv6 -j REJECT --reject-with icmp6-port-unreachable

           
   
### **7.-Ejecute la utilidad de auditoría de seguridad lynis en su sistema y trate de identificar las acciones de securización detectadas así como los consejos sobre las que se deberían contemplar.**

  1)Instalamos lynis -> `apt install lynis`

  2)Executámolo e esperamos a ver os resultados -> `lynis audit system`

  3)Mirar servicios/puertos/carpetas... que tocamos durante as practicas 1,2,3, entender porque non está ben securizado e saber como solucionar (non fai falta arreglar)











