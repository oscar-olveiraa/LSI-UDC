# **Práctica 1 Legislación y Seguridad Informática**

IP->10.11.48.135

### **1.- Configure su máquina virtual de laboratorio con los datos proporcionados por el profesor. Analice los ficheros básicos de configuración (interfaces, hosts, resolv.conf, nsswitch.conf, sources.list, etc.)**

* ### configuración archivo *interfaces*:

	1-Vamos ao directorio como ROOT `/etc/network`

	2-Entramos dentro do archivo 'interfaces' usando un editor de texto(nano,pico,vim...) -> `nano interfaces`

	3-Editamos o archivo mencionado da seguinte maneira (no meu caso en nano):

		auto lo ens33 ens34
 
		iface lo inet loopback
 
		iface ens33 inet static
 
  			address 10.11.48.135
    
  			netmask 255.255.254.0
    
   			broadcast 10.11.49.255
     
   			network 10.11.48.0
     
  			gateway 10.11.48.1
     
  		iface ens34 inet static
  
  			address 10.11.50.135
      
  			netmask 255.255.254.0
      
  			broadcast 10.11.51.255
      
  			network 10.11.50.0

	(Auto->o puerto levantarase despois de un reset do equipo // iface: Sirve para indicar o interfaz // inet ou inet6: Identifica cómo vai obtener o direccionamiento do puerto)
      
	4-Gardamos (ctrl+o) e salimos (ctrl+x)

	5-Executamos o comando -> `systemctl restart networking.service`  (reinicia o servicio da rede do servidor)

	6-Comprobamos conexion con -> `ifconfig -a` (mostra informacion de todas as interfaces de rede, tanto activas como inactivas)

	7-Facemos un reboot -> `reboot`

* ### Mirar archivo *hosts*:

  	1-Vamos ao directorio `/etc`

	2-Entramos dentro do archivo hosts. Este archivo asigna nombres de hosts direccions de ip. Este archivo ten pouca utilidade xa que o DNS xa fai ese traballo pero podemos asignar nos dominios localmente-> `nano 	hosts` :
  
  		127.0.0.1       localhost
  
		127.0.1.1       debian
  

		#The following lines are desirable for IPv6 capable hosts

		::1     localhost ip6-localhost ip6-loopback

		ff02::1 ip6-allnodes

		ff02::2 ip6-allrouters


* ### Mirar archivo *resolv.conf*:

	1-Vamos ao directorio `/etc`

	2-Entramos dentro do archivo resolv.conf. Este archivo funciona para a resolución de nomes dentro de unha red determinada ou Internet, reguistrando aqui os servidores DNS de confianza. Hai varios servidores DNS para obter redundancia -> `nano resolv.conf`

  		domain udc.pri
  
		search udc.pri

		nameserver 10.8.12.49

		nameserver 10.8.12.50

		nameserver 10.8.12.47


* ### Mirar archivo *nsswitch.conf*:

	1-Vamos ao directorio `/etc`
  
	2-Entramos dentro do archivo nsswitch.conf. Este archivo define o orden de busqueda da BD de red -> `nano nsswitch.conf`

  		passwd:         files systemd
  
		group:          files systemd

		shadow:         files

		gshadow:        files


		hosts:          files mdns4_minimal [NOTFOUND=return] dns myhostname

		networks:       files


		protocols:      db files

		services:       db files

		ethers:         db files

		rpc:            db files


		netgroup:       nis

 
 * ### Mirar archivo *source.list*:

	1-Vamos ao directorio `/etc/apt`
   
	2-Entramos dentro do archivo source.list. Este archivo sirve para que o apt sepa en que repositorios ten que encontrar os paquetes -> `nano source.list`

   		deb http://deb.debian.org/debian/ buster main
   
		deb-src http://deb.debian.org/debian/ buster main


		deb https://deb.debian.org/debian-security buster-security main contrib

		deb-src https://deb.debian.org/debian-security buster-security main contrib


		deb http://security.debian.org/debian-security buster/updates main

		deb-src http://security.debian.org/debian-security buster/updates main



### **2.-¿Qué distro y versión tiene la máquina inicialmente entregada?. Actualice su máquina a la última versión estable disponible.**

* ### Mirar a distro e a version inicial:
  
  	1-Executamos o seguinte comando, dando como resultado -> `lsb_release -a`
  

  		No LSB modules are available.
  
		Distributor ID:	Debian
  
		Description:	Debian GNU/Linux 10 (buster)
  
		Release:	10
  
		Codename:	buster

	**Empezamos a actualizar a máquina:**

  	2-Facemos un update e un upgrade do equipo (como root) -> `apt update && apt upgrade` (si poñemos a extension a ambos -y todas as preguntas que faga durante a execución do comando será automaticamente si)
  
  	3-Entramos dentro do archivo *source.list* e modificamos da seguinte maneira (si hai comentarios(lineas iniciadas con #) podemos deixalos):
  
		deb http://deb.debian.org/debian/ bullseye main non-free contrib
		deb-src http://deb.debian.org/debian/ bullseye main non-free contrib

		deb http://security.debian.org/debian-security bullseye-security/updates main contrib non-free
		deb-src http://security.debian.org/debian-security bullseye-security/updates main contrib non-free

		deb http://deb.debian.org/debian/ bullseye-updates main contrib non-free
		deb-src http://deb.debian.org/debian/ bullseye-updates main contrib non-free

  	4-Executamos `apt update`
  
  	5-Executamos `apt full-upgrade`
  
  	6-Rebotamos a máquina `reboot`

   	A estas alturas si arrancamos a maquina e volvemos a executar o comando do paso 1 deberiamos ver:

	    No LSB modules are available.
  
		Distributor ID:	Debian
  
		Description:	Debian GNU/Linux 11 (bullseye)
  
		Release:	11
  
		Codename:	bullseye

  	Este ano temos unha nova version de debian, a 12 e para actulizala ao maximo facemos o seguinte :
  
  	1-Facemos un update e un upgrade

   	2-Volvemos ao *source.list* e modificamos de esta maneira:

  		deb http://deb.debian.org/debian/ bookworm main non-free contrib
		deb-src http://deb.debian.org/debian/ bookworm main non-free contrib

		deb http://security.debian.org/debian-security bookworm-security/updates main contrib non-free
		deb-src http://security.debian.org/debian-security bookworm-security/updates main contrib non-free

		deb http://deb.debian.org/debian/ bookworm-updates main contrib non-free
		deb-src http://deb.debian.org/debian/ bookworm-updates main contrib non-free

  	3-Facemos un update e un full-upgrade

   	4-Volvemos a reiniciar a máquina

  	5-Volvemos a comprobar a distro e version actual e sería:

        No LSB modules are available.
  
		Distributor ID: Debian
  
		Description:    Debian GNU/Linux 12 (bookworm)
  
		Release:        12
  
		Codename:       bookworm 



### **3.-Identifique la secuencia completa de arranque de una máquina basada en la distribución de referencia (desde la pulsación del botón de arranque hasta la pantalla de login).**

*  ¿Qué target por defecto tiene su máquina?. 
   
   	O target e un enlace simbólico (ficheiro ou directorio que se encontra en un sitio diferente á estructura de directorios) ao target verdadeiro
    
			1-Executamos -> systemctl get-default

*  Cómo podría cambiar el target de arranque?. 
   
   	Cambiamos de target xa que o que esta por defecto consume moito no arranque do equipo. Este target está dentro do lvl5 en Sys5 e cambiamos para o lvl3 (multi-user.target)
    
    		1-Executamos o comando -> systemctl set-default nomeTarget

*  ¿Qué targets tiene su sistema y en qué estado se encuentran?. ¿Y los services?. 

    		1-Para ver os targets, executamos o comando -> systemctl list-unit-files --type=target

  			2-Para ver os servicio, executamos o comando -> systemctl list-unit-files --type=service
  			  Si queremos ver unha breve descripcion do servicio poñemos -> systemctl list-units --type=service

*  Obtenga la relación de servicios de su sistema y su estado. ¿Qué otro tipo de unidades existen?. 

    		1-Para ver os servicios co seu estado executamos -> systemctl list-units --type=service --all

      		2-Para ver outros tipos de unidades facemos -> systemctl list-units --t help


### **4.-Determine los tiempos aproximados de botado de su kernel y del userspace. Obtenga la relación de los tiempos de ejecución de los services de su sistema.**

	1-Para mirar os tempos de botado -> systemctl-analyze

  	2-Para mirar os tempos de ejecucions dos servicios -> systemctl-analyze blame

### **5.-Investigue si alguno de los servicios del sistema falla. Pruebe algunas de las opciones del sistema de registro journald. Obtenga toda la información journald referente al proceso de botado de la máquina. ¿Qué hace el systemd-timesyncd?.**

 	1-Para ver os servicios que fallan -> systemctl list-units --type=service --failed

  	2-Journald é un sistema de rexistros de sucesos, encargado de xestionar estos registros de eventos e rexistros do sistemas en un formato estructurado e eficiente. Algunhas das opcions son -b, -u:

   		-journalctl -u SERVICIO -> mostra o log de un servicio (seguimento de un archivo para todos os acontecementos que afectan a un proceso particular).
     
     	-journalctl -b -> ver os rexistros relacionados co inicio actual do sistema (o log do boot actual)

	 	-journalctl -k -> rexistros relacionados solamente co kernel
   
   	3-O systemd-timesyncd ten como función principal proporcionar a sincronización de tempo no sistema con servidores NTP remotos

### **6.-Identifique y cambie los principales parámetros de su segundo interface de red (ens34). Configure un segundo interface lógico. Al terminar, déjelo como estaba.**

*  Cambiar parametros ens34:

        1-Xa está feito no ejercicio 1, no apartado de interfaces

*  Configurar unha interfaz lóxica: Estas interfaces virtuales utilizanse para asignar múltiples direcciones IP ou configuracions de red adicionales a mesma interfaz física(ens34)para asi aislar o trafico e mellorar a seguridade. 

   Para facelo facemos os seguintes pasos:

        1-Executamos o comando -> ifconfig ens34:1 192.168.1.1 netmask 255.255.255.0 (usar unha ip que estea fora do rango para evitar conflictos)

    	2-Levantamos a interfaz -> ifconfig ens34:1 up

        3-Comprobamos que teñamos ahora 4 interfaces (ens33, ens34, ens34:1, lo(loopback)) -> ifconfig

        4-Si queremos gardar a interfaz, añadimola ao archivo interfaces. Si queremos eliminala facemos un reboot da máquina

### **7.-¿Qué rutas (routing) están definidas en su sistema?. Incluya una nueva ruta estática a una determinada red.**

 	1-Para ver sas rutas definidas do sistema -> ip route show  // route -n

   	2-Para añadir unha nova ruta -> ip route add 10.11.52.0/24 via 10.11.48.1 (ip route add a.a.a.a/b via gateway)

### **8.-En el apartado d) se ha familiarizado con los services que corren en su sistema. ¿Son necesarios todos ellos?. Si identifica servicios no necesarios, proceda adecuadamente. Una limpieza no le vendrá mal a su 	 equipo, tanto desde el punto de vista de la seguridad, como del rendimiento.**

   Para quitar servicios executamos os comandos `systemctl disable nome_Servicio` e despois `systemctl mask nome_Servicio`. A diferencencia entre deixamos en disable a facerlle un mask é que si o deixamos o disable e o servicio 
   ten dependencias, ao reinicar o ordenador esas dependencias poden chamar ao servicio e volvelo a activar mentras que con un mask queda permanentemente deshabilitado. Para quitarlle o mask facemos `systemctl unmask 
   nome_Servicio` e para quitar un disable `systemctl enable nome_Servicio`. Cousas a ter en conta: 

   - Para mirar dependencias -> `systemctl list-dependencies SERVICIO/TARGET/SOCKET`

   - Para mirar a cadena do camiño crítico(unidades que consumen mais tempo) -> `systemd-analyze critical-chain`

   - Para sacar unha gráfica secuencial as unidades que interveñen no arranque -> `systemd-analyze plot` . Esto generá un texto xml que si o copias e pegas en un bloc de notas con extension .html abreche a grafica no navegador

   - Si cando cambias o target non baixa o tempo de userspace e eliminando algun servicio tampouco baixa, facendo un `systemd-analyze plot` ves o que che tarda en realidad. Si é menos do que che indica en terminal, cando volves a 
     maquina fas un reboot e miras outra vez. Asi os tempos deberia aparecer xa ben, polo menos no meu caso. 
   
   
   Lista de servicio que quitei:

   * *accounts-daemon* -> servicio para GNOME , innecesario xa que non usamos o graphical.target:

   * *alsa-units.service* -> subsistema de sonido estándar que proporciona a infraestructura para xestionar dispositivos de sonido, controladores e aplicacions relacionadas co sonido

   * *avahi-daemon.service* -> proporciona funcionalidad para o descubrimiento e a comunicación de servicios en unha red local sin facer unha configuracion manual como un mDNS

   * *bluetooth.service* -> non vamos usar esto na practica asi que a tomar por culo

   * *cups.service // cups-browsed-service* -> gestionar o servidor de impresión e proporcionar a funcionalidad esencial para a administración de impresoras, a configuración e o procesamiento de traballos de impresión. A segunda 
      é un servicio adicional que se usa para a deteccion automatica da impresora en red local. Curiosidad, si antes de quitar este servicio facemos un lsof -i -P veremos os puertos que escoita a nosa máquina. Cups usa o puerto 
      631 pero ao deshabilitalo desaparece

   * *keyboard-setup.service* -> esta unidad utilizase para configurar o diseño del teclado durante o proceso de inicio del sistema, innecesario

   * *e2scrub_reap* -> verifica todos os metadatos en un sistema de archivos montado si o sistema de archivos reside en un volumen lóxico LVM (tecnoloxía que permite a flexibilidade dos dispositivos de almacenamiento, como discos 
      duros y particiones

   * *plymouth-quit-wait.service* -> este servicio controla o tempo que se mostra a pantalla de inicio ou de cierre antes de que o sistema continúe ca carga dos compoñentes do sistema operativo ou se apague. Como non 
      temos entorno grafico, aire

   * *plymouth.service* -> gestiona a presentación da pantalla de inicio durante o proceso de arranque e apagado do sistema

   * *plymouth-quit.service* -> deter o servizo de Plymouth despois de que o sistema se iniciase completamente e se cargara o entorno de traballo principal.

   * *plymouth-halt.service* -> está relacionado co manexo da pantalla de cierre, é dicir, a pantalla que se mostra cando se apaga ou reinicia o SO. De plymouth hasta aquí porque os outros teñen depencias fuertes e si os quitas 
      sube o tempo do userspace

   Para baixar mais o tempo miramos a secuencia de arranque -> `journalctl -b` . No meu caso tiña servicios relacionados co GNOME(interfaz gráfica). Para quitalos facemos `apt remove --purge SERVICIO`:
   
   * *pipewire.service* -> simplifica a xestión de audio e video no sistema, así como proporcionar unha infraestructura para aplicacións multimedia -> `apt remove --purge pipewire`

   * *pulseaudio.service* -> obtorga funcionalidad de audio. Actúa como unha capa intermedia entre as aplicacións de audio e o hardware de sonido do sistema -> `apt remove --purge pulseaudio`

   * *GNOME* -> algún servicio ou socket que teña GNOME ou chame a GNOME -> `apt remove --purge 'gnome*'` (o * indica que todo que teña gnome eliminase)

   * *gvfs* -> sistema de archivos virtual de GNOME -> `apt  remove --purge gvfs`

   * *tracker-extract* -> forma parte do GNOME, extrae e analiza metadatos contido textual de archivos para indexalos y buscalos mais facilmente e así máis accesibles para o usuario ->  `apt remove --purge tracker-extract`

   Outras ferramentas/comandos para eliminar archivos basura:

   * `apt autoclean`: Elimina da caché paquetes de versions antiguas.
   
   * `apt clean`: Elimina todos os paquetes da caché.

   * `apt autoremove`: Elimina aqueles paquetes perdidos, paquetes instalados como dependencias de outras instalacións, que xa non están.

   * `apt autoremove --purge`: a opción --purge sirve para outras chamadas de apt para borrar archivos de configuración.
    
   Con este tuneado a túa maquina debería andar entre 8-10s, polo menos no meu caso.
    
### **9.-Diseñe y configure un pequeño “script” y defina la correspondiente unidad de tipo service para que se ejecute en el proceso de botado de su máquina**

   Para crear un script temos que crear un servicio para que se execute ese script de forma autónoma.

   - Creación do script:

        1-Diriximonos ao path */usr/local/bin*

     	2-Creamos un archivo con extensión .sh e programamos o script -> `nano script.sh`

     		#! /bin/bash
     		#O meu script -> Crea un archivo txt e garda en el unha frase

     		mensaje="ejecucion do script -> todo correcto"
     		archivo="/usr/local/bin/script.txt"

     		echo "$mensaje">"$archivo"
     		echo "mensaje gardado en $archivo"

        3-Creamos os servicio dirixindonos a ruta */etc/systemd/system*

     		[Unit]
     		Description=O meu servicio para o script	
	
            [Service]
     		Type=oneshot
     		ExecStart=/usr/local/bin/script.sh
     		RemainAfterExit=yes

	        [Install]
     		WantedBy=multi-user.target

        4-Activamos o servicio -> `systemctl enable meu.service`

     	5-Comprobamos no directorio */usr/local/bin/* si se creou o .txt

     
	
### **10.-Identifique las conexiones de red abiertas a y desde su equipo.**

   Executamos os comando -> `netstat -netua`
   
   Hai unha ferramenta mais moderna, ss, onde a diferencia é rendimento, eficiencia e ten info máis detallada -> `ss -netua`
   
   Outros parámetros(sirve tanto para netstat como para ss):
   
   *  -tlun -> mostra solo as conexions activas
     
   * -a -> mostra conexions en puertos
      
   * -l -> conexións e sockets que solo escoitan 

### **11.-Nuestro sistema es el encargado de gestionar la CPU, memoria, red, etc., como soporte a los datos y procesos. Monitorice en “tiempo real” la información relevante de los procesos del sistema y los recursos 	  consumidos. Monitorice en “tiempo real” las conexiones de su sistema.**

  Para facer os seguimento en tempo real dos recursos e procesos executamos -> `top`

  Para ver en tempo real as conexions do sistema -> `netstat -netuac`

### **12.-Un primer nivel de filtrado de servicios los constituyen los tcp-wrappers. Configure el tcp-wrapper de su sistema (basado en los ficheros hosts.allow y hosts.deny) para permitir conexiones SSH a un determinado 	  conjunto de IPs y denegar al resto. ¿Qué política general de filtrado ha aplicado?. ¿Es lo mismo el tcp-wrapper que un firewall?. Procure en este proceso no perder conectividad con su máquina. No se olvide que trabaja contra ella en remoto por ssh.**

### **13.-Existen múltiples paquetes para la gestión de logs (syslog, syslog-ng, rsyslog). Utilizando el rsyslog pruebe su sistema de log local. Pruebe también el journald.**

   Rsyslog é unha ferramenta utilizada para a xestión e envío de logs(grabación secuencial nun archivo de todos os acontecementos que afectan a un proceso particular).

   Para enviar un mensaje de log -> `logger "mensaje"`

   Para comprobar -> `tail -n /var/log/syslog` (tail é un comando para mostrar as últimas líneas de un archivo de texto ou a saída de un fluxo de datos en tiempo real, o parametro -n é para sacar os últimos n mensajes e indicamos 
   o directorio donde se garda os logs). Si queremos sacar todo o log por pantalla facemos un cat /var/log/syslog

### **14.-Configure IPv6 6to4 y pruebe ping6 y ssh sobre dicho protocolo. ¿Qué hace su tcp-wrapper en las conexiones ssh en IPv6? Modifique su tcp-wapper siguiendo el criterio del apartado h). ¿Necesita IPv6?. ¿Cómo se 	  deshabilita IPv6 en su equipo?**
	
   
  
  



