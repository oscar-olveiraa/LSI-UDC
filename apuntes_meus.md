SEMANA 1:
TEMA 1: FUNDAMETOS E CATEGORIA DE ATAQUES:
md5, sha2, sha3
NTP-netowrk time protocol
df->comando para ver discos/particions

*vulnerabilidades-CVE-NIST-CVSS-CWE-CPE-NVD
 -cve é unha lista de vulnerabilidades que existen. CVE (ano_encontrado-codigo) e con unha descripcion
 -nvd é base de datos de vulnerabilidades levado pola empresa NIST (proporciona a info das cve)
 -cvss asignaselle un numero a unha debilidade que indica o nivel de gravedad da vulnerabilidade
 -cwe tipologias das vulnerabilidades (lista de tipos de debilidades de software)
 -cpe identifica diferentes plataformas de traballo
 -oval e un lenguaxe que usa  para identificar vulnerabilidades e evaluar poliicas de seguridad
 -nexus, lanza unha prueba para saber as vulnerabilidades da maquina
 -exploits->para atacar esa vulnerabilidade
 -vector ataque tipo red e unha vulnerabilidade que podo atacar en red, remotamente
 -vector ataque adyacent->poder explotar vulnerabilidades dentro da propia rede fisica e loxica
 -vulnerabildades tipo local e tipo fisica
 -(0-days) e unha vulnerabilidade que non aparece en ningunha base de datos, non existe parche e non esta normalizada. Deixa de ser 0-day unha vez o parche esté dispoñible

Exemplo de vulnerabilidades:

- Shellshock: permite la ejecución de líneas de comandos
- Heartbleed: agujero de seguridad en la biblioteca OpenSSL
- Poodle: exploit man-in-the-middle

*Amenazas: unha amenaza é un peligro posible que podría explotar unha vulnerabilidad. Exemplo ->sniffers, troyanos, malwares...








*Ataque: 
fuerza bruta->craqueo de contraseñas
	poisoning(envenamiento)->arp poisoning, dns poisoning
	Injection->os injection, sql injection
	pode ser intencionados ou accidentales
	Categorias:
		Origen-Flujo-Destino
		Ataques por formato
		Desbordamientos de pilas(buffers overflow)
	intercepcion->sniffing, escucha de lineas
	modificacion->dificil de detectar, desbordamento de pila, cross side scripting
	spoofing->subplantacion de ip

Tipos de ataques:
-Activos:

Un ataque activo intenta alterar os recursos do sistema ou afectar ao funcionamiento. Implican algunha modificación do fluxo de datos ou a creación de un fluxo falso. Éstes presentan características opostas aos pasivos: son difíciles de previr por completo e o obxetivo é detectalos y recuperarse de eles.

-Pasivos:

Un ataque pasivo intenta coñecer ou facer uso de información do sistema, pero non afecta aos recursos do mismo. Éstes danse en forma de escoita ou de observación non autorizada das transmisions para obter información que se esté transmitiendo.
Los ataques pasivos son moi difíciles de detectar, xa que no implican alteracións dos datos. Contra estos ataques debense poner máis énfasis na prevención que na detección. Unha posible solución -> cifrar o trafico


Resumen:
- Un sistema de autenticación que permite un número limitado de intentos -> Vulnerabilidad
- Un software que permita facer pruebas de autenticación de forma automática -> Amenaza
- Executar o software para que actúe sobre un sistema -> Ataque


	


mac,ip,puertos,sesiones,navegado-servidor con flujo http
proxy->e como un firewall pero mellor, é unha maquina intermedia.
cross-site-scripting -> xss -> tipo de ataque a unha consola
interrupcion->representacion (O->|)(borrado de bases de datos,ficheiros, romper fisicamente algo)
deteccion inmediata(IDS(analizan trafico de rede, o que pasa nas maquinas, logs, p.e->suricata, snort), IPS(detectan incidentes, toman accions para parar ataques ou incidentes, normalmente fanse en firewalls->snort, suricata), sensores())
keyjack(inalambrico)
mousejack(inalambrico)

debian-ssh
-------------------------------------
SEMANA 2:

origen-destino-flujo
	-Intercepcion:o flujo parase (deteccion->ids(SNORT, SURICATA),ips(ambos sistemas activos, 1º deten e o 2º prevee),sensores). Pode ser en red ou en host. Ejemplos:destruccion hardware, borrado 			programas/archivos/bd, fallos en SO ou apps(vulnerabilidades)
	-Ataques->DoS, DDoS(denegacion de servicios)(logico vs inundacion), para defendernos de estos seria con traffic shaping e QoS
	-Defensa -> Proxy-> con squid ou apache. 

DWDM -> algo sobre fibra optica
ERTMS -> sistema europeo de xestion de trafico ferroviario
Maltego -> servicio para encontrar información sobre persoas y empresas en Internet
BackBone->red dos nodos principales(elviña-zapateira-ferrol)
IEEE802.11x ->estandar para tecnoloxías de redes inalámbricas
T568A // T568B -> estandar de cableado

Os ataques de interrupcion son ataques contra a confidencialidad
-------------------------------------
SEMANA 3:
origen-destino-flujo
	-modificacion: ataque contra a integridad, contra as funcions hash, modificar unha base de datos(sql injection), modificacion de programas(cracking, spiderwar, troyanos), modificacion mensajes e 
	sesiones(modificacion paquetes), buffer overflow. Spoofing(subplantacion de algo).
	IP4->32b // IP6->128B // MAC->48b
	-generacion/fabricacion: ataque contra a autenticidad. Añadir transacciones falsa, un email falso, un sms falso, un servidor dns spoofing

TEMA 2: INFORMATION GATHERING

-Hosts discovery -> Descubrir as máquinas que hai en unha red(esquema dos equipos de unha organizacion->maquinas directas->servidor web, servidor email, servidor dns, maquinas que estan na dmz). Forma de facer host discovery -> enviar un ping a cada dirección IP de un rango y ver quen responde. Esto ten 2 problemas: non todas as máquinas responden ao ping y é un proceso lento. 
-FingerPrinting(saber cousas de port scannig, a partir dos puertos podo saber informacion e saber as vulnerabilidades. Pode ser pasivo(buscar webs) ou activo(port scanning)
-Port scannig(descubro maquinas e despois escaneo os puertos a esa máquina para saber que puertos ten levantados) 

Intervalos dos puertos:

Puertos ben conocidos (well-known ports):
  - Son puertos reservados no rango 1 a 1023 que foron rexistrados para un servicio determinado.
  - Alguns sistemas exigen privilegios especiales para asociar aplicacions a estos puertos.
Puertos rexistrados (registered ports).
  - Rango 1024 a 49151.
  - A diferencia cos anteriores é que no se esixen privilexios especiales
Puertos dinámicos e/ou privados.
  - 49152 a 65535.
  - Usanse dinámicamente ou ben por servizos privados de unha compañía  

-FootPrinting(coller informacion de paginas webs, wikis, redes sociales)
-Google Hacking // Google Dorks 
-OSINT(open source inteligent)->colle informacion publica
-kaly linux->distro de linux que ven xa con ferramentas de seguridad e hacking
-net rangos -> nic(para crear dominios, podesmos recoller informacion sobre direccionamento)
	       ripe // ncc -> coordinan os nic de todos os paises

Ip.maquinas:
-ping->os routers filtran trafico icmp polo que non funcionan
-traceroute->ttl vais sumando 1 e si chega a 0 responde con un error. Si todo vai ben vamos vendo con esto todos os routers e maquinas que pasa un ordenador para conectarse. Si filtra o trafico icmp, non aparece información. Traceroute en tcp/udp podemos saltarnos ese filtro.
-Varios servidores dns en cada dominio para que haba redundancia(resolv.conf)
-DNS:
  *solucion directa(resolve ip) e solucion inversa(resolve nombre).  
  *Sistema jerarquico. Ten un punto(raiz) que ten moitos servidores e delegan en outros servicios(forma de arbol). Son sevidores con unha bd en named(creo), que garda todas as ips dos dominios que delega ese     servidor. 
  *En un dominio temos servidores primarios(teño que mantelos, darlle a informacion) e os servidores secundarios(segun os configures, cada x tempo conectase aos primarios e volcan a información). Nos     primarios hay registros A(solucion directa), registros AAAA, registros cname, registros ns, registro mx(servidor correo electronico), registro ptr(resolucion inversa). 
  *Ferramentas : dnsenum, dnsmap, dnsrecon, nslookup (poñemos nslookup ls udc.es, collemos toda a base de datos dns, hoxe en dia está bloqueado), dig(version moderna de nslookup). Si non podo facer transferencia de zona, facemos dnsenum udc.es ou dnsrecon -r 193.144.x.1-192.144.x.254 ou nmap. Para evitar estas cousas, meten os registros A pero non ten registro ptr. 
  *Si facemos DNS cache snooping(en cache xa que si fas unha peticion, esa peticion gardase en cache entonces sabes que estuvo buscando esa organizacion), dnscon -t snoop -n x.x.x.serverdns -D <file>. Para   facer cache snooping podemos facelo no recursivo(un flag recursivemode=0), si facemos eso quere decir que ou si che da algo de cache ainda que o normal e que o modo no recursivo estea desactivado. Cos tempos tamen podemos saber si está en cache ou no xa que si tarda mais ou menos sabemos si esta en cache ou no. 

1),2),3) non sei

4)Puertos
Podemos mover os servicios de puerto. Hai que facer pruebas para saber que servicios corren en ese puerto de esa organizacion.
Pasar a traver de un ips indentificarianche

5)Fingerprinting servicios

6)Fingerprinting puertos

7)Mapa

8)Busqueda de vulnearabilidades(openvag, nessus, nikto, zap, w3nf(os tres ultimos é para apps web))

Exploits->netesploits
CoBal Trike, theFatRat(crear troyanos)
Shodan->bd de exploits(NVD->bd para vulnerabilidades)






-------------------------------------
SEMANA 4:

PayLoads: 
   Single -> explotar vulnerabilidad
   Stagers -> unha vez explotada a vulnerabilidad conectar a tua maquina ca maquina atacada
   Stages -> utilidades para a maquina atacada
   ferramenta meterpreter -> Elimina logs e non deixar que haba un rastro do teu ataque. Podes acceder a webcam, ao teclado do atacado
   ferramenta set -> Automatizar sin coñecemento para facer ataques en ambito ingieneria social

Firewall -> capa 3 e capa 4 e pode que en capa 2 tamen
DMZ->zona donde estan os servidores nunha empresa. Hoxe en dia unha empresa ten varios dmz

Capa 7(aplicacion):
WAF (web aplication firewall)-> ferramenta modsecurity, cloudfare, infoguar

Explotacions:
Escalada de privilegios e pivoting(utilizae outra maquina en vez da miña para atacar)
Ofuscación
 
-1º tipo de fw:
Firewall sin control de estado -> capa 2,3,4 gestiona ips e puertos
Firewall con control de estado -> sigue os flags syns, ack, fin ...(producese o handshake de forma correcta)
nmap -> ver puertos abertos, cerrados, escoitando
nmap -P0 -p 80 -sI x.x.x.x maquina_a_escanear

-Port scan:
ipid incrementa en 1 si o puerto está cerrado e si esta incrementado en 2 quere decir que o puerto escoita a maquina á atacar. Esto con un fw control de estado non funcionaría
ipid secuencial, con pouco trafico de red -> candidatos para maquinas zombies






OWASP-> OWASP top 10->algo de aplicativos web -> código aberto dedicado a determinar e combatir as causas que fan que o software sea inseguro 
1)Broken access protocol (control de acceso)


2)Criptographic failures. Id's ingresos, path traversal, permisos mal postos nos ficheiros


3)Inyecciones->sql inyection, so inyection, LDAP inyection(sobre servidores), xss(cros-site scripting)


4)Insecure design


5)security misconfiguration(configuracions incorrectas das aplicacions)->p.e: os buckets (amazon web service). Aqui tamen está xxe(xml (external entities))


6)Vulnerable and outdated components


7)Autentificacion(roubo cookie autentificacion, roubo de tokens de sesiones)


8)Soft and Data integrity


9)monitorizacion and loging


10)server and request forgery




ASVS(Aplicattion Security Verification Standard)-> estandar de owasp
ZAP-> ferramenta de owasp para ver vulnerabilidades de aplicativos web
blindelephant->ferramenta como zap
WAF(firewall  de aplicacions web)->con wcf ww00f www.----- fai un fingerprinting para saber si hai un waf


-Fingerprinting and scanning: ferramenta nmap
1ºgeneracion->nc -v -n -w1 10.11.48.x 21-180 -> comando para ver os puertos e aqueles que estean abertos saca unha cabecera
2ºgeneracion->
3ºgeneracion->icmp 
4ºgeneracion -> aplicacion continua->proc/sys/net -> para tunear a máquina cambiando parámetros
Ofuscacion->axuste de parámetros para intentar engañar nas técnicas de fingerprinting. Pámetros->ttl(ten un valor e cando vai pasando polo router aumenta 1 e si chega ao destino como 0 dropease a máquina e aborta  a operacion, windows traballa con 128 en linux con 64)->proc/sys/net/ipv4/ipdefault_ttl(si cambio de 64 a 128, asi en vez de ter un linux, o atacante pensa que teño un windows)

-------------------------------------
SEMANA 5:
4ºgeneracion continuacion:
Iptables/ntf->ferramentas para configurar os firewalls
iptables -t Mangle -I output -j ttl -ttl-set 53->todos os paquetes que pasan polo firewall cambia o seu ttl a 53
lynx -head -dump http...
smtp->'vrfy' non se usa pero 'rcpt to' si -> para cambiar estos parámetros smtp-usue... sirve para mirar que xente está en esa rede ou no

-port scannig:
hpings -c 1 -s -p 22 x.x.x.x -> si me devolve un syns-ack é que seguramente o recibira e si hai un reset, non lle chegou pero hai algo ahi
nmap -s A -p 22,48,443,512 -> mando acks a unha máquina. Si recibo un reset quere decir que a outra máquina non ten un firewall de control de estado
nmap -s A -pU 512,123 -> en udp
nmap -sP 10.11.48.0/24 ->host discovering de esa máquina. Envía un ping e si responde hai unha máquina ainda que normalmente está todo filtrado por icmp. 
nmap -D x.x.x.x, x.x.x.x, x.x.x.x -> decoy scanning -> spoofea as ip
open,closed,filtred,unfiltred, open filtred, closed filtred -> etiquetas de nmap para indicar información sobre os puertos
nmap -T x
nmap -O x.x.x.x -> fingerpriting de operativos e version con un procentaje de  que operativo e version ten esa máquina
nmap -s S -sV -p 22,48,443,512 -> fingerprintg de servicios para saber  que servicios corren en esa máquina



nbtscan-> scaner para red de envios en windows
ping e traceroute en algún punto non pillan ips polo icmp
traceroute -T (tcp) // traceroute -U (udp)-> si non funciona traceroute, facemos esto. Manda un sync a un servidor web e daría todo o traceado das ips hasta o servidor

HandSchake de UDP E TCP:







Outros tipo de fw(a parte de con control de estado e sin control de estado):
-modo router -> router en acceso a internet que lle asignas un access list(ips e puertos que deixo pasar)
-NAT -> é como modo router pero con traduccions nating
-transparentes -> son fw que traballan en capa2, non teñen ip, son inexpugnables porque solo saben que hai un fw os servidores locales.
-de nova generación->2 fw en modo cluster que ainda que se caia un, podes seguir accedendo aos servidores.

maltego, netglub-> informacion sobre information gathering
metadato-> ferramenta creepy->recolectar fotos e si leva metadatos de posicionamento podemos sacar informacion

spider -> buscador de google-> procesos de spidering(colle un servidor web(index.html-> raiz)e recollo todos os servidores webs que depende do raiz)-> é como si se enganchara a todo servicios web(página raíz -> index.html) entón abrese un árbol. Tamén sirve para ver vulnerabilidades, estudios de mercado flitrando información e sacando un arbol de webs e recorrelo
crawler -> analsis semánticos para buscar vulnerabilidades
scrapper -> focalizar determinada información para mirar comparativas como no caso dos distintos precios de proveedores en amazon
hardening -> da consellos a nivel de seguridade do sistema -> ferramenta en linux(#lynis audit system-> primeiro aparece logs donde se vai gardando info sobre a ferramenta, despois aparece info sobre o so e despois unha lista dos paquetes que nos recomenda instalar para mellorar a seguridade do noso sistema, p.e -> apt listbugs, needrestart(mirar que servicios necesitan un restart), debsusms).

strace -e true=%file ssh.service -> aparece todas as librerias e archivos que usa ese servicio


-------------------------------------
SEMANA 6:
Redudndancia -> Seguridad y rendimiento

PAE(Physichl Address Extension)->para poder ampliar direccionamento de memoria (con unha arqut de 32bits podo ter 64GB de RAM)
DEP(Data Exception Prevention)->as zonas de memoria dedicada a datos (a pila) controlaas como de non ejecución(preveen ataques de desbordamento de pila)
/etc/security/limits.conf -> cambiar parámetros para poñer limites e non petar a máquina(normalmente personalizase cando en una maquina traballlan varias personas)
ficheros core son volcados de memoria -> cando peta o kernel fai unha imagen da memoria actual 
/etc/pam.d/common.password -> pam é para ficheiros e carpetas que pasan por pasos de autentificacion. 
	rounds=2000000 (cando hasheo o password, faino 19999999 mais veces)-> esto fai que a hora de craquear os passwords, tarde mais

Comandos:	
chage -l lsi  -> para saber cando caduca o password, canto lle queda
passwd -e lsi -> para definir cada canto tempo teño que cambiar as contraseñas

Estos tres defineen as politicas para definir as normas de como teñen que ser as contraseñas:
pam.cracklib
pam.passwdqc
pwquality(nova version de pam.cracklib)

Comando:
umask 022 -> cando creas un ficheiro, veñen por defectos os permisos con este código

/etc/profile -> con etc todos os usuarios que entran na miña máquina afecta a todo o mundo
$home/profile
si fago umask 022 /etc/profile -> todo o mundo que se conecte a miña máquina e crea un ficheiro tendrá esos permisos

Particionar os discos duros -> swap podemos poñelo en outro disco duro e facer traballos en paralelo (+seguridad  e +rendimento)
Con lvm podemos aumentar ou reducir os tamaños de unha particion(cando instalas linux dache unha opcion para ter esto)

echo 1 > /proc/sys/kernel/moduler_disabled -> con esto intento cargar un modulo no kernel -> con modprobe podo cargar modulos

TEMA 3: OCULTACION E PRIVACIDADE:
NAT non ten nada de ocultación
A ocultacion ten que ser en todas as capas OSI
FTP (File Transfer Protocol): un protocolo estándar de red utilizado para a transferencia de archivos entre sistemas conectados a unha red TCP/IP, como Internet ou unha red local
Hai web-based proxy(servicio que se accede a través de un navegador web) e open proxy.
Usos na ocultacion:
proxy http
proxy sock -> para calquer puerto
teremos a sua conf /etc/socks.conf e dentro temos os campos direct 127.0.0.1 255.255.255.255
							    direct 10.11.48.0 255.255.254.0
							    sockd @=x.x.x.x  0.0.0.0. 0.0.0.0

si alguen colle a tua ip e usaa a traves de dous ou tres proxys polo medio, é imposible identificar quen fixo o mal ca túa ip

Honey -> estructuras trampa (señuelos)-> sirve para que sean atacadas e ver que fai o atacante para entrar en unha infraestructura
 
Tipos de proxys:
Proxy transaparente: non da privacidad nin ocultación, usan un campos de http forward que fai que sepa a tua traza na rede
Proxy anónimo:
Proxy alta anonimicidad ou proxy élite:
Proxy ruidosos: meten info falsa

Comando:
export http-proxy=http//xxxx:318 -> en esa ip ten que haber un proxy que escoite as peticions
export http-proxy=http//user:password:xxxx:puerto
export ftp-proxy=ftp//xxxx:318
estos comandos meteriamolos en un script no path /etc/profile

ferramenta para montar proxys -> squid, apache

Craqueo de wifi:
airomon-ng -> tarjeta wifi en modo monitor(esnifar todo trafico que hai no aire)
airodump-ng captura -> wifi modo monitor e garda en un archivo o trafico
airoplay-ng -> tira da wifi da victima, queda sin conexion a tua maquina
airocrock-ng -> crack handshakes de wpa2
airmon-ng start wlan0 (nombre tarjeta red da maquina)-> pon a tarjeta de red en modo monitor
airodump-ng mon0(algo da tarjeta red) -> saca info do canal, das macs e o nombre do sitio donde estas conectado
airdump-ng --canal x -bssid x:x:x:x(mac) -w captura(handshake) mon0
airoplay-ng -0 1 -a x(mac) -c x(mac) mon0
airoplay-ng -w dicc captura

Handshake entre maquina e punto de acceso:
punto de acceso do router manda un anonce(numero aleatorio que genera o punto de acceso) á miña máquina, a miña maquina monta un ptk=pmk+anounce+snonce(numero aleatorio que genera a miña máquina)+mac(punto acceso)+mac(maquina)
A miña maquina manda o snonce+mic(hash(ptk)). Todo este handshake snifoo cos anteriores comandos e gardoo no archivo captura
o unico cando genero ptk, non sei é o pmk, por fuerza bruta vou probando no diccionario no archivo captura todo tipo de codigos para o pmk e si un pmk genera un ptk que coincide co mic xa teriamos xa acceso a esa wifi

wifite -> ferramenta para craquear wifis
wps -> estandar da wifi que se basa en un identificados de 7 digitos decimales. Si sabes ese codigo tes acceso a wifi nese punto de acceso

Fluxion -> ferramenta que suplanta un punto de acceso. Os routers manda uns frames que fai que cando estas cerca do router apareceche os simbolo da wifi de ese router. Esa ferramemta cando te metes en un router e si se che abre unha ventana que pide un presharedkey e llo das pois estas fatidiado :(

Ferramentas de craqueo de hashes:
cain&abelz
john the ripper

unshadow /etc/passwd /etc/shadow ficheiro

No fichiro shadow(ficheiro onde se garda informacion sobre os meus passwords creo):
root [$1$ ->md5 // $6$->sha 512bits] [Salt (Entre 8-16 caracteres(cod en base64))] [pass hash salteado(de 13 a non sei que caracteres en base64)]
crackear passwd pode se moi complicado porque entre o salt (como max 64^16 combinacions) e ademais si poñemos rounds(explicado un pouco mais arriba) acaba sendo imposible

hashcat -> recuperacion de contraseñas
cewl -> usa spidering a unha url que se lle pasa e devolve unha lista de palabras que se pode usar para crackear contraseñas 
muntator/crunk , thehardnester

-------------------------------------
SEMANA 7:

ferramenta para craquear hashes:
hash-identifier
hash-id
findmyhash->busca en un repositorio de unha base de datos si ese hash xa foi craqueado ou no

password guessing ->ataque en servicios interativos de autentificacion por exemplo Un formulario, usuario/password. Normalmente deixa un registro dos intento en un log. 
Podemos filtrar as ips, os usuarios en enviar unha inmensa cantidad de paqueteria(n-1).Por exemplo si mando passwords e cando se resetea o servicio volvo a mandar n-1. Como tarda en restartearse a miña maquina para mandar a seguinte trama n-1, podo esperar poñendo retardos nas rafagas ou cambiar a ip e facer estas rafagas n-1 en cada ip.

Ferramentas para password guessing:
medusa
n-crack
hydra

captchas -> evita que che fagan un password guessing, por ejemplo o de escribir un codigo que se ve mal ou marcar imagenes onde hai semaforos

medusa -d -> todos os modulos que podo atacar con password guessing
medusa -M ssh -q
medusa -h ipcompa -u lsi -P p.txt -M ssh -f ->p.txt seria un diccionario e ir probando para craquear
medusa -H fich-IP -U -> mal escrito creo

Proteccion para password-guessing:
en iptables podemos poñer hash-limit -> En conexions ssh ou en un formulario podemos limitar os intentos de autentificacion
fail2ban -> ferramenta para mellorar a seguridade de un servidor protexendoo de ataques de forza bruta e outros tipos de ataques
ossec hips(host ips -> sistema de prevencion de instrusions). Funciona a nivel de rede. Esto mira nos logs para mirar os intentos de autenficacion que se fixeron e bloquealo

wget -r -k http://.... -> fai spidering 
wget -r -k -l2 http://.... -> descarga 2 niveles
wget -r -k -H http://.... ->

securizar grub:
gru-mkpasswd pbkdf2
che pide un password e posteriormente generache unha cadena(hash 512 do password que lle pusxetes)
en /etc/grubd/40_custom poñemso estas duas lineas:
set superuser=root
passwd-pbkdf2 root hash512

ataques tempest -> 

reballing(resoldar) reflow -> as placas bases eran aleacion de plomo e eran moi efectivas para as placas pero moi contaminantes. Cas novas aleacions con plata, cando vai mal, aplicabas calor á placa e volvia a funcionar ben. Deixouse de usar plomo e aplicouse outra aleacion e non era tan bo

Seguridad WiFi:

WPE ->

WPA->

WPA2->

WPS->

krack attack -> primer ataque contra o protocolo WPA2 que non se basa en password guessing dirixindose principalmente ao 4-way handshake
wpa3-> cambia o hadnshake, usa un algoritmo de dragonblood. Incrementa a clave (128 a 192). Os craqueos de wifi explicados antes xa deixarian de funcionar

TCPDump ->







borrado seguro(para non recuperar a info xa que con rm si que se pode recuperar):
srm
shred
wipe
dd if=/dev/random f=/dev/sdb -> borrado completo xa que sobrescribe no disco duro. Si aplicamos en un bucle 30 veces, é inmposible recuperar esa info
sfill -> borra todo o espacio libre de un disco duro
ssawp -> borra a particion de swapping
smem -> borrado seguro da ram

dns leaks ->

Red tor (The Onion Routing):
https://geekland.eu/que-es-y-como-funciona-la-red-tor/ (explicado mais ou menos)
anonimato e privacidad
ten directorios que conteñen os nodos tor(unha máquina) que son os que consiguen o anonimato
nodos de entrada/nodos intermedios/nodos de salida
teño onion proxy na miña máquina e onion routers (nos nodos)
cada sesion do nodo ten unha clave
a miña máquina sabe todas claves dos nodos por onde pasan os meus paquetes

Tipos de entidades:
- Onion Router (OR): Encaminadores, nodos da red Tor. Calquer usuario pode actuar como nodo. Os nodos se comunicanse entre sí mediante TLS. Alguns, ademáis, funcionan como servicio de directorio, proporcionan lista de ORs, con información de cada un.
- Onion Proxy (OP): Son os usuarios finales. Software que permite: Consultar servicio de directorio; Establecer circuitos aleatorios a través de la red; Xestionar conexions de aplicacions do usuario.

Funcionamento:
cando quero un paquete -> en cada nodo crease unha capa ao rededor do paquete da clave de ese nodo(cifrado), en ese cifrado tamen está a info para que o paquete sepa cal é o siguiente nodo a que ten que enviar 
cando me chega a min o paquete, si por exemplo hai 3 nodos intermendios, o paquete teria 3 capas. Devolvo a miña petición e cada nodo vai quitando unha capa hasta que o último nodo quita a ultima capa e manda esa peticion ao servidor 





Problemas de tor: 
-o ultimo nodo sabe o contido de esa capa polo que si é unha máquina maliciosa pode esnifarme a paqueteria
-o rendimento 

tor vegas -> axusta o tamaño das colas de tor con respeto a latencia
tor nola -> preven a latencia que vai a ver
ATM ->
whonix ->

Adblock Plus:
- Bloquear anuncios
- Permitir anuncios aceptables
- Desactivar seguimiento
- Desactivar dominios de malware
- Desactivar botón de redes sociales

NoScript:
Extensión de navegadores. Bloquea código JavaScript, Java, Flash, Silverlight. O usuario pode permitir a execución de código de certos sitios de confianza, añadindoos a unha lista (whitelist).
Proporciona protección frente a ataques como XSS, CSRF, clickjacking, man-in-the-middle e DNS rebinding

HTTPS Everywhere -> Forza a usar SSL sempre que sea posible

todo o que un navegador non se poda indexar xa seria deep web

podemos encadenar proxy -> http://proxy:puertohttp://proxy2:puertohttp://proxy3:puerto
http://www.google.com/traslate?longpain=es|en&u=http://........

port forwarding:
monto un ssh en casa que escoite no puerto 443
para esto usamos dns dinámico(xa que a miña ip cambia). Esto asigna un nombre dominio e sempre apunta a ip da miña casa
en /etc/ssh.conf-> cambio port 443 , facemos systemctl restart do servicio ssh
na máquina de lsi:
como hai firewall que solo escoita puerto 80 e 443, non podo acceder ao puerto 2128, facemos esto:
conectamonos por ssh a maquina da miña house -> ssh x.x.x.x(da casa) -p 443 -l user -L 2128:x.x.x.x:2128
cando fago un http://localhost:2128, faria unha peticion a miña casa que escoita en 443 e a miña casa faría a peticion ao puerto 2128, e asi podo acceder a puertos que non sean 80 nin 443
ssh -p 443 -fN -D x.x.x.x:1080 user@x.x.x.x(casa) -> mirar que fai

Info sobre servidores nx:

-------------------------------------
SEMANA 8:

corkscrew -> para saltarse proxy http

port knocking:
sirve que levante o servicio con un programa feito por min que pase esa peticion por un firewall para que solo me deixe levantalo a min e cando me desconecte, ese programa manda que se tire ese servicio
/etc/knocking.conf:
[openSSH]
sequence=70000, 7015, 9001
sq_timeout=10
tcpflag=SYN
COMMNAD= iptables -A input -s %IP%
[close SSH]
sequence=70000, 7015, 9001
sq_timeout=10
tcpflag=SYN

Para activalo:
knockd x.x.x.x 7000,7015,9001
ssh x.x.x.x
knockd x.x.x.x 6000, 6015, 9018

TEMA 4: INTERCEPTACIÓN:
libro moi recomendable -> LAN switch security what hackers know about your switch security layer 2 cisco press
VLAN -> configurase con un trunk port. P.e: en vez de ter unha infraestructura en cada facultad para secretaria, montase unha infraestructura para que todas as secretarias estean no mismo sitio.



VLAN:
Agrupación lógica de dispositivos que se basa na configuración de switches.
Podense crear en un switch (o conjunto de switches) diferentes dominios de difusión, asignando cada porto do switch a unha agrupación (VLAN) concreta.
Para unir VLANs que están definidas en varios switches podese crear un enlace especial chamado trunk, polo que flúe tráfico de varias VLANs.

VLAN: Trunk
Os portos que están asignados a unha única VLAN coñecense como portos de acceso
Os portos que están asignados a varias VLANs (enlace trunk), coñecense como portos troncales
Cómo sabe un switch a qué VLAN pertence unha trama cando a recibe por un porto troncal -> protocolo 802.11Q

Protocolo 802.11Q tamen chamada DTP permite añadir unha etiqueta de 4 bytes a cabecera das tramas ethernet, en donde inclue o nº de VLAN ao que pertence dita trama

yersinia -> ferramenta para atacar en capa 2. Ataca a STP, DTP, 802.1q, 802.1x

ataques:
switch spoofing -> yersinia fai que a tua máquina sea como un switch(suplanta o switch) e podes entrar si non está ben securizado a calquer vlan xa que os firewalls traballan normalmente en capa 3
double tagging -> ocurre cando un paquete de rede xa etiquetado con información de VLAN é novamente etiquetado con información de VLAN adicional.

BPDU -> fala o protocolo STP. Esto fai que fale STP entre eles e fai que sea unha estructura en arbol e evitamos os bucles que pode ocurrir ca paqueteria entres varios routers

Ataques BPDU:
podo convertirme no route bridge


Proteccion de BDPU:
root bridge guard -> 

bdpu guard -> filtrar o BDPU




-------------------------------------
SEMANA 9:

ICMP Redirect:
Esto non o ten un router, teno normalmente unha máquina. É unha máquina que fai de router.
ettercapt -q.. -M icp:80:90...[mac router]/10.11.48.1[ip router]/ /ip a que redigimos[victima]//
proc/sys/net/ipv4/conf/all/accept_redirect -> está a 1 e si o poñemos a 0 non deixa facer icmp redirect 
........................../server_redirect -> si está a 1, solamente router confiables
........................../set_redirects -> a tua máquina pode mandar redirects ou no (0 ou 1)
/etc/sysctl.conf -> net.ipv4.conf.all.accept_redirect=0
		    .................server_redirect=1

systemctl -p -> todas as variables que editamos en sysctl.conf restarteanse

DHCP spoofing:
con esto configuramos nos á victima o seu interfaz de red
para evitar este ataque -> dhcp snooping
Alguns switches dispoñen de Dynamic Arp Inspection e DHCP Snooping -> detectan o ataque e poden parar automáticamente o puerto do atacante

Port stealing:
Un conmutador de red ten puertos e asignaselle as maquinas que se conectas macs dinámicas

O atacante envía multitud de tramas ARP (pero no con el objetivo de saturar a CAM)
As tramas ARP teñen como MAC origen a MAC da(s) víctima(s)
O obxetivo é que o switch "aprenda" que a víctima se encontre en ese puerto e así dirixa o tráfico hacia él, é como si roubara o puerto da víctima
- Una vez que el atacante recibe paquetes "robados", detiene el proceso de
Técnica útil para capturar tráfico en entorno conmutado, cando ARP spoofing non é efectivo (p.ej. hay mapeado ARP estático)
ettercap -q... -M port[remote][tree] /x.x.x.x//

NDP:
Sirve en ipv6 para o descubrimiento de veciños, resolución de direccions e a autoconfiguración de direcciones.
en ipv6 non hai arp, non hai broadcast, funciona con icmp
para facer ataques por ipv6 facemolo con ndp

DNS Spoofing/DNS poisoning(envenena a caché do server dns):
falsear os resolvedores de dns
É un servicio inseguro, non fai falta logearse e moitas veces vai por UDP, non por TCP
DNS Sec:
Extension dns seguro
pode auntenticarte, ten integridad pero non cifra nada
DoT(dns over tls) -> con esto cifrariase o que fai dns sec polo que configurariamos os dous á vez
EvilGrade -> 


ARP:
Protocolo de resolución de direccions, forma en que as redes TCP/IP resolven as direcciones MAC basándose nas direccions IP de destino.
ARP Spoofing/ARP Poisoning:
Técnica para infiltrarse en red Ethernet conmutada, que permite ao atacante leer paquetes de datos na LAN, modificar o tráfico ou deteneo 
Ferramentas que implementan os ataques: ettercap, Cain y Abel, suit Dsniff

ARP spoofing con https
ettercap
sslstrip
sslstrip2 
inyeccion de certificado()
sslstrip -> estando eu no medio, eu falo co server en https e co cliente en http
HSTS -> evita o problema de sslstrip. Ahora na cabeceira ten un numero que é un token con caducidad
sslstrip2 -> modifica ese token e fai que caduque en ese momentose

Ettercap:
Ferramenta de seguridad gratuita que pode usarse para análisis de protocolos de rede e para auditorías de seguridade
Permite realizar ataques man-in-the-middle en una LAN

#arp -d x.x.x.x (esto elimina a ip)
#arp -s x.x.x.x x:x:x:x ( esto fai fija unha máquina)
#arptables -A input --source x:x:x:x[mac] -j DROP (é un firewall de capa dous)
#ip link set dw ens33 arp off (tiramos o protocolo arp)
#ip neigh flush all (borra a tabla arp)
Para protexer arp -> snort(ips conocido(evita arp spoofing...))
#nast -c 

Flooding: 
protexemonos con unicast flooding protection-> mira o numero de paquetes que chega ao conmutador por un puerto e reducelle o nº de paquetes que mande e evita que caia el se caia abaixo
con ettercap hai un plugin con -P ranf_floot que manda por defect o cada 2microseg 200 paquetes e est o fai que os conmutadores se caia abaixo, ou vaian mais lento o fai que estea modo half enton estarái modo compartido e podo esnifar a paqueteria de esa 

con port scan ou port mirroring -> monto un ips casero
este puerto do conmutador ten que ir moi ben protexido e pode crear un cuello de botella xa que todos os puertos do conmmutador mandan o seu tráfico por este puerto 
podemos crear un trunk port para evitar ese cuello de botella polo que é como si tuveramos 3 interfaces e multiplicase x3 o ancho de banda. Si por exemplo se fastidia un puerto, teño os outros(creo redundancia e tamen securizo)

Modos balanceadores de carga
Mode 0 -> round robin

Mode 1 -> Active-BackUp

Mode 2 -> Balance XOR -> (MacOrigen XOR MacDestino)mod (nº interfaces)

Mode 3 -> modo broadcast

Mode 4 -> 802.3ad

Mode 5 -> balanceo de carga de transmision adpatable

Mode 6 -> balance ALB(adaptable como envio e recepcion)

#apt install ifenslave
#echo bounding >> /etc/module
#mo





En /etc/network/interfaces:
iface bond0 inet static
address 10.11.x.y
networking
broadcast
:
:
slaves ens33 ens34 ens35
bond_mode 0
____________
____________

Port Security:
modo por defecto do puerto -> shutdown. Si atacan a ese puerto:
dropea a paqueteria
manda un snmp(Simple Network Management Protocol) -> protocolo utilizado para a xestión e supervisión de dispositivos en unha rede
fai un disable do puerto

Solución:
#inet giga 0/2 (puerto 0 fila 2) xa que os conmutadores ten filas de puertos
#switch port-security maximo 4

TAP (TEST ACCESS PORTS)
Esnifa paqueteria entre o meu ordenador e o firewall e esa paqueteria vai a un SOC (traffic strumming ou algo asi)
Si apagamos o tap non pasa nada, sigue funcionando o flujo de conexión
Normalmente, están configurados estos taps en empresas media grande e tamen teñen dous firewalls en modo cluster(redundancia) (firewalls sofisticados)
Este tipo de firewalls traballan en todos as capas, integran WAT, tamen controlan hipervisores, controlan o flujo da virtualizacion, tamén teñen IPS, integra sistemas de autentificacion, pode analizar o trafico en busca de troyanos, virus, exploits..., como hai paqueteria cifrada ou si abrimos unha vpn o firewall non veria esa paqueteria entón son eles os encargados de cifrar as cousas.

SOC:
Está ligado cos SIEM(traballan con logs)
EDR alimentase de agentes de servicios temporales, que danlle info aos edr
EDR alimentase dos taps


As estafetas do correo electronico van vinculados aos SORBS(si mandamos algun correo e ten algo que ten na base de datos dos SORBS peta)

-------------------------------------
SEMANA 10:

#ngrep -d ens33 -x (con ngrep busca cadenas no trafico de rede)

Side Jacking:
Rouba unha cookie de autentificacion, coockie de trazado(a info que che saca ao navegador por unha pagina), configuracion de perfiles.
a cookie leva a informacion codificada de tamaño fijo
en html5 ten o webstorage. Local storage garda para sempre esa info.
cookies persistentes, supercookies, zombiecookies... Distintas tecnoloxias que fai o mismo que unha cookie pero con outros mecanismos

TEMA 5: ATAQUES DOS  E DDOS:

DoS loxico/semántico (producido por unha vulnerabilidad, malas configuracions). Protexémonos parcheando. 
Exemplo deste ataque -> ping of Death(PoD):



DoS inundacion/flooding(meteselle moita carga). Factor de amplificacion(numero de paquetes que lle chegan en paralelo, un a un ou de 100 en 100)
Exemplo deste ataque -> Ping flood:


Tipos de ataques por inundación:
Directos -> slowhttptest (ip oirgen-ip destino)
Reflectivos -> inyecto paquetes a unhas, maquinas cheganlle e responden á máquina destino. Podese parar con fw de control de estado.(como non se iniciou o handshake coas ips dos meus usarios, dropeanse)
Con UDP podese configurar para control estado. Un paquete con cliente que ten normalmente un puerto alto, e cando pasa polo fw ponselle un sync e chega ao servidor con un puerto baixo entón xa estaria.

Trafico de broadcast debe de filtrarse e quedar na LAN, non pode salir fora xa que podese devolver ese trafico a unha maquina da LAN e tirala abaixo.

hping3, scapy -> ferramentas para meter paquetes na rede

DDoS -> botnets:



SYN Flood o que fai e querer encher a cola de paquetes do kernel e a tua maquina non abre xa conexions ao estar chea
/proc/sys/net/ipv4/tcp_mac_syn_backlog -> está a 128 e podo aumetalo, p.e 256 (si a aumento demasiado cargome a máquina xa que tendria pouco rendimento)
/proc/sys/net/ipv4/tcp_synack_netnes -> tempo máximo de respostas de paquetes

SYN Proxy -> o syn en vez de facelo eu, faino o proxy e cando acaba de facer o hadshake, chegame o paquete.

SYN Cache -> en tcb crea unha tabla hash con minima info para poder facer conexions

iptables -A input -p tcp --dport 80 -m hashlimit --hash-limit-ysto 50/min --hash-barst 400 --hash-limit -nude scrip --hash-limit http -j accept
iptables -A input -p tcp --dport 22 -m hashimit --hashlimit 1/min --hash-limit-mode  scrip --conntract --cstate NEW -j accept (control de estado, new é cando fai o sync e fai 1 por minuto)

Traffic shaping e packet shaping -> para gestionar ancho de banda (vinculado a QoS)

Reverse Proxies (normalmente en pares para facer un cluster) -> para o acceso aos servidores web xa que son os servidores mais atacados. Reciben info do cliente, van a pagina, collen a respuesta e entregan ao cliente a respuesta.

SMTP:
Mailbox -> ten miles de usuarios. Un ficheiro por cada usuario (poucos ficherios pero grandes)
MailDir -> un ficheiro por cada correo electronico dos usuarios (moitos ficherios pero pequenos)

Pruebas de carga -> jmetev, apache bench (simular por exemplo que hai 100 usuarios no servidor e saca informes do test)

ip spoofing -> usar ips que non de outros para mandar paquetes
packit -b 0 -c0 -s R -d 10.11.48.x -F s -s 2000 -D 80 (directo)
packit -b 0 -c0 -s 10.11.48.x -d R -F s -s 2000 -D 80 (reflectivo)
hping3
estos comando fai que o tcb da maquina se encha (onde se alamacena todos os syncs que fai a tua maquina)

sndp (ndp securizado) -> usa pki(infraestructura de clave publica)

fake_router6 ens33 -> manda un router advertisment (RA) e as maquinas activan o SLAAC, enchese o procesador ao 100% e caese a máquina
/proc/sys/net/ipv6/ ten uns ficheiros e en un ten accept _RA 1 e pasariamos a telo a 0 para non recibir ese ataque

iframe nas paxinas web bloqueanse para non recibir ataques

-------------------------------------
SEMANA 11:

Para poñer o router en modo monitor:
#airmon-ng start wfan0
#airodump-ng eth0
#aireplay-ng -0 0 -a x:x:x:x
#aireplay-ng -0 0 -a x:x:x:x -c x:x:x:x

Estandar 802.11w para proteccion de wLAN 

wIPS -> sistema de prevencion de instrusion en redes WiFi

ACRYLIC ferramenta que ten unha grafica RSSI(para mirar a potencia dos puntos de acceso). Ten mais utilidades
Con RSSI -40 -60 moi ben
Con RSSI -60 sigue estando ben
Con RSSI >= -70 perdemos moito recursos

Espectro da wifi 2.4GHz:(mais interferencias pero maior alcance)
Vai de 2400MHz a 2470MHz
Xestion do espectro e repartese en canales[2400MHz(1     6     11)2470MHz]
						    2     7
						     3     8
						      4     9
							5    10
  
  
                                            
Espectro wifi 5GHz:(antes non era tan potente como 2.4GHz pero ahora con wifi6 é moi potente)
Ten 25 canales e non se solapan (en 2.4GHz si que se solapan). Empeza enumerandose en 36

OWISAMP -> metodoloxia para mirar a seguridad das wifi

wifihammer -> barrido completo de todas as wifis e autenticaste en elas enton deixas sin wifi a todos  e tes todo o espectro para ti.

RTBL -> para integrar no meu firewall. RTBL ten unh base de datos de ips e ten un ranking que si ten un valor baixo o firewall dropeariao
RBLMon -> si aparece un valor moi baixo avisanos

SBL -> chequean si esos servidores de correo que lle mandas ten se3rvidores mal configurados
XBL -> macrobase de datos para ver maquinas que foron hackeadas ( integralo no fw para dropear as maquinas que se conecten) 

TEMA 6:  FIREWALLING:

iptables, ip6tables, ethetables, arptables, ipset(definir conxunto de direccions)
Traballa a nivel kernel, todo o paquete que chega procesao.

reglas INPUT -> paquetes que entran á miña maquina
reglas OUTPUT -> reglas de salida
reglas FORWARD -> cando entra un paquete onde ip destino non é a miña maquina, é outra (temos p.e duas tajetas de rede e un é para a miña LAN  e outro para a rede da empresa)
reglas NAT -> cambio de ip e puertos para facer nating
reglas MANGLE -> modificacions dos paquetes

cadena -> agrupacions de reglas. Moi importante a secuencia das reglas. Si salta unha accion non se sigue procesando esa secuencia. Tamen  se pode loggear e queda o paquete ahi e siguese procesando as outras reglas

cadena prerouting -> reglas para paquetes de entrada
si non entra en prerouting, vai a forwarding e despois a postrouting





		prerouting -> input
		    |
Interfaz	forward		    procesar
		    |
		postrouting <-output

Tablas:
MANGLE -> (pre, input, forwa, output, post)
NAT -> (pre, out, post)
FILTER -> (input, forwa, out)

Estructura comando iptables:
iptables -t [tabla] comando cadena condicion accion opcions
		    añadir
                    borrar
                    insretar

#iptables -t FILTER -A INPUT -p TCP --dport 123 -j DROP
						   ACCEPT
						   REJECT

Non facer un firwall persistente. Cada vez que queiramos executar o script, facemolo a man
Si non se especifica unha tabla, é como si o executara en filter
-s -> destino
-d -> origen

iptables -F (borra todas as reglas)
iptables -x (borra todas as cadenas)
iptables -P input DROP (politicas por defecto, sempre drop)
iptables -P output DROP (politicas por defecto, sempre drop)
iptables -p forward DROP (politicas por defecto, sempre drop)
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -A lo -j ACCEPT
iptables -A INPUT -s 10.11.48.cliente -d 10.11.48.miña -P TCP --dport 514 -j ACCEPT(servidor de rsyslog)
iptables -A INPUT -s 10.11.48.cliente -d 10.11.48.miña -P UDP --dport 123 -j ACCEPT(servidor de ntp)
iptables -A OUTPUT -s 10.11.48.miña -d 10.11.48.cliente -P TCP --sport 514 -j ACCEPT
iptables -A OUTPUT -s 10.11.48.miña -d 10.11.48.cliente -P UDP --sport 123 -j ACCEPT
iptables -A INPUT -s red/mascara -d 10.11.48.miña -P TCP --dport 22 -j ACCEPT
iptables -A OUTPUT -s 10.11.48.miña -d 10.11.48.cliente -P TCP --sport 514 -j ACCEPT

falta mirar ssh, dns, repositorios source.list, grafana, prometheus, splunk, ipv6

-------------------------------------
(SEMANA 12)

Non facelo persistente xa que cada vez que haba un reboot lanzase o fw.

Flags:
new
established
related

meter tamen UDP

iptables -A input -P TCP --dport 22 -s 10.11.30.0/24 -d 10.11.48.14 -m countrack --cstate NEW, ESTABLISHED -j ACCEPT -j ACCEPT (aceptaria os sync da miña rede)
iptables -A output -P TCP --dport 22 -s 10.11.48.14 -d 10.11.30.0/24 -m countrack --cstate ESTABLISHED,RELATED -j ACCEPT -j ACCEPT

eu como cliente:

iptables -A output -P TCP --dport 22 -s 10.11.48.14 -d 10.11.30.0/24 -m countrack --cstate NEW, ESTABLISHED -j ACCEPT -j ACCEPT
iptables -A input -P TCP --dport 22 -s 10.11.48.14 -d 10.11.30.0/24 -m countrack --cstate ESTABLISHED,RELATED -j ACCEPT -j ACCEPT

outra forma mais simplificada:

iptables -A input -m countrack --cstate ESTABLISHED, RELATED -j ACCEPT (aceptaria os sync da miña rede)
iptables -A output -m countrack --cstate ESTABLISHED,RELATED -j ACCEPT
iptables -A input -P TCP --dport 22 -s 10.11.30.0/24 -d 10.11.48.14 -m countrack --cstate NEW -j ACCEPT


meter ao final:

iptables -A input -P TCP -j REJECT --reject null tcp-reset	
iptables -A input -P UDP -j REJECT --reject null icmp-port-unrecharble 

Para que se lanze o fw:
1)Crear un servicio
2)poñer en /etc/network/interfaces
  post-up script_fw
3)instalar unha ferramenta (esto si queremos que fagamos persistente -> na vida real si, nas practicas no)
#apt install iptables-persistant
#iptables persistans /etc/iptables/rulesv4
#iptables __ iptables-pers.start

para ipv6:
ip6tables -A input -P tcp --dport 22 _____ -s fe80:________

rexistrar os accesos a máquina:
iptables -A input -p tcp --dport 80 -m string string "/etc/passwd" -j LOG --log-ip-option --log-tcp-options --log-parse "access passwd" -j DROP
iptables -A input -p tcp --dport 22 -j LOG --log-prefice "intento non autorizado" --log-level-4

netfilter -> framework para que faga cousas ca paquetería en cada capa. 


iptables -t filter -A forward -s x.x.x.x -d x.x.x.x -p tcp --dport 514 -m countrack -cstate NEW -j ACCEPT
nft add rule filter forward ip saddr x.x.x.x ip daddr x.x.x.x tcp dport 514 ct state NEW ACCEPT (con ip en nft xa integra capa 2,3,4)

psad -> identifica posibles ataques á maquina
fwbuilder -> para contruir fw con iptables ou nftables
