# **Práctica 2 Legislación e Seguridad Informática**

### **1.-Instale el ettercap y pruebe sus opciones básicas en línea de comando.**

   * Instalación de ettercap

         apt install ettercap-text-only

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

  * Identifique los campos de cabecera de un paquete TCP

  * Filtre la captura para obtener el tráfico HTTP

  * Obtenga los distintos “objetos” del tráfico HTTP (imágenes, pdfs, etc.)

  * Visualice la paquetería TCP de una determinada sesión.

  * Sobre el total de la paquetería obtenga estadísticas del tráfico por protocolo como fuente de información para un análisis básico del tráfico.

  * Obtenga información del tráfico de las distintas “conversaciones” mantenidas.

  * Obtenga direcciones finales del tráfico de los distintos protocolos como mecanismo para determinar qué circula por nuestras redes.
               
     
