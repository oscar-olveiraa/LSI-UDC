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

  Para crear o tunel ssh -> `ssh -L 9090:localhost:8080 lsi@10.11.48.118 -N`

  Comprobación (o 'cliente' ten que estar escoitando mentres o servidor lle manda mensaxes):

  Quen estableza o tunel -> `echo "Hola desde mi máquina local" | nc -q 0 localhost 9090` (mirar o do -q)

  Quen estea como 'cliente', recibirá ese mensaxe cando estea escoitando -> `nc -l -p 8080`

#
  
E) “Exporte” un directorio y “móntelo” de forma remota sobre un túnel SSH.

#

  F) PARA PLANTEAR DE FORMA TEÓRICA.: Securice su sevidor considerando que únicamente dará servicio ssh para sesiones de usuario desde determinadas IPs.



### **2.-Tomando como base de trabajo el servidor Apache2**
   
  A. Configure una Autoridad Certificadora en su equipo.

  B. Cree su propio certificado para ser firmado por la Autoridad Certificadora. Bueno, y fírmelo.
  
  C. Configure su Apache para que únicamente proporcione acceso a un determinado directorio del árbol web bajo la condición del uso de SSL. Considere que si su la clave privada está cifrada en el proceso de arranque su 
     máquina le solicitará la correspondiente frase de paso, pudiendo dejarla inalcanzable para su sesión ssh de trabajo.



### **3.-Tomando como base de trabajo el openVPN deberá configurar una VPN entre dos equipos virtuales del laboratorio que garanticen la confidencialidad entre sus comunicaciones.**


### **6.-En este punto, cada máquina virtual será servidor y cliente de diversos servicios (NTP, syslog, ssh, web, etc.). Configure un “firewall stateful” de máquina adecuado a la situación actual de su máquina.**



### **7.-Ejecute la utilidad de auditoría de seguridad lynis en su sistema y trate de identificar las acciones de securización detectadas así como los consejos sobre las que se deberían contemplar.**











