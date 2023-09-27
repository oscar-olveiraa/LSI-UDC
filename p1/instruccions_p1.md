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

	2-Entramos dentro do archivo resolv.conf. Este archivo funciona para a resolución de nomes dentro de unha red determinada ou Internet, reguistrando aqui os servidores DNS de confianza -> `nano resolv.conf`

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

   	A estas alturas si arrancamos a maquina e volvemos a executar o comando do paso 1 deberiamnos ver:

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

### **5.-Investigue si alguno de los servicios del sistema falla. Pruebe algunas de las opciones del sistema de registro journald. Obtenga toda la información journald referente al proceso de botado de la máquina. ¿Qué 	hace el systemd-timesyncd?.**

 	1-Para ver os servicios que fallan -> systemctl list-units --type=service --failed

  	2-Journald é un sistema de rexistros de sucesos. Algunhas das opcions son -b, -u:

   		-journalctl -u SERVICIO -> mostra o log de un servicio (seguimento de un archivo para todos os acontecementos que afectan a un proceso particular).
     
     	-journalctl -b -> ver os rexistros relacionados co inicio actual do sistema (o log do boot actual)

	 	-journalctl -k -> rexistros relacionados solamente co kernel
   
   	3-O systemd-timesyncd ten como función principal proporcionar a sincronización de tempo no sistema con servidores NTP remotos

### **6.-Identifique y cambie los principales parámetros de su segundo interface de red (ens34). Configure un segundo interface lógico. Al terminar, déjelo como estaba.**

### **7.-¿Qué rutas (routing) están definidas en su sistema?. Incluya una nueva ruta estática a una determinada red.**

 	1-Para ver sas rutas definidas do sistema -> ip route show  // route -n

   	2-Para añadir unha nova ruta -> ip route add 10.11.52.0/24 via 10.11.48.1 (ip route add a.a.a.a/b via gateway)

### **8.-En el apartado d) se ha familiarizado con los services que corren en su sistema. ¿Son necesarios todos ellos?. Si identifica servicios no necesarios, proceda adecuadamente. Una limpieza no le vendrá mal a su 	 equipo, tanto desde el punto de vista de la seguridad, como del rendimiento.**
    
### **9.-Diseñe y configure un pequeño “script” y defina la correspondiente unidad de tipo service para que se ejecute en el proceso de botado de su máquina**

### **10.-Identifique las conexiones de red abiertas a y desde su equipo.**

### **11.-Nuestro sistema es el encargado de gestionar la CPU, memoria, red, etc., como soporte a los datos y procesos. Monitorice en “tiempo real” la información relevante de los procesos del sistema y los recursos 	  consumidos. Monitorice en “tiempo real” las conexiones de su sistema.**

### **12.-Un primer nivel de filtrado de servicios los constituyen los tcp-wrappers. Configure el tcp-wrapper de su sistema (basado en los ficheros hosts.allow y hosts.deny) para permitir conexiones SSH a un determinado 	  conjunto de IPs y denegar al resto. ¿Qué política general de filtrado ha aplicado?. ¿Es lo mismo el tcp-wrapper que un firewall?. Procure en este proceso no perder conectividad con su máquina. No se olvide que 	  trabaja contra ella en remoto por ssh.**

### **13.-Existen múltiples paquetes para la gestión de logs (syslog, syslog-ng, rsyslog). Utilizando el rsyslog pruebe su sistema de log local. Pruebe también el journald.**

### **14.-Configure IPv6 6to4 y pruebe ping6 y ssh sobre dicho protocolo. ¿Qué hace su tcp-wrapper en las conexiones ssh en IPv6? Modifique su tcp-wapper siguiendo el criterio del apartado h). ¿Necesita IPv6?. ¿Cómo se 	  deshabilita IPv6 en su equipo?**
	
   
  
  



