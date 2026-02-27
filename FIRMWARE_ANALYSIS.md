================================================================================
ANÁLISIS FIRMWARE HG8145V5-V500R020C10SPC212
Huawei ONT - Optical Network Terminal
================================================================================

## 1. INTERFACES WEB DISPONIBLES
--------------------------------------------------------------------------------

Además de la interfaz principal en 192.168.100.1, el firmware
contiene múltiples interfaces web para diferentes ISPs:

1. frame_Stc
   Descripción: Interfaz STC Arabia Saudita
   Ruta: /home/runner/work/firmware-HG8145V5-V500R020C10SPC212/firmware-HG8145V5-V500R020C10SPC212/web/frame_Stc

2. FrameAISAP
   Descripción: Interfaz AIS Tailandia
   Ruta: /home/runner/work/firmware-HG8145V5-V500R020C10SPC212/firmware-HG8145V5-V500R020C10SPC212/web/FrameAISAP

3. frame_du
   Descripción: Interfaz desconocida
   Ruta: /home/runner/work/firmware-HG8145V5-V500R020C10SPC212/firmware-HG8145V5-V500R020C10SPC212/web/frame_du

4. frame_IraqO3
   Descripción: Interfaz Iraq O3
   Ruta: /home/runner/work/firmware-HG8145V5-V500R020C10SPC212/firmware-HG8145V5-V500R020C10SPC212/web/frame_IraqO3

5. frame_pccw
   Descripción: Interfaz PCCW Hong Kong
   Ruta: /home/runner/work/firmware-HG8145V5-V500R020C10SPC212/firmware-HG8145V5-V500R020C10SPC212/web/frame_pccw

6. frame_telmex
   Descripción: Interfaz desconocida
   Ruta: /home/runner/work/firmware-HG8145V5-V500R020C10SPC212/firmware-HG8145V5-V500R020C10SPC212/web/frame_telmex

7. frame_XGPON
   Descripción: Interfaz XGPON
   Ruta: /home/runner/work/firmware-HG8145V5-V500R020C10SPC212/firmware-HG8145V5-V500R020C10SPC212/web/frame_XGPON

8. frame_xgponglobe
   Descripción: Interfaz Globe Philippines
   Ruta: /home/runner/work/firmware-HG8145V5-V500R020C10SPC212/firmware-HG8145V5-V500R020C10SPC212/web/frame_xgponglobe

9. menu
   Descripción: Interfaz desconocida
   Ruta: /home/runner/work/firmware-HG8145V5-V500R020C10SPC212/firmware-HG8145V5-V500R020C10SPC212/web/menu

10. frame_Arabic
   Descripción: Interfaz árabe
   Ruta: /home/runner/work/firmware-HG8145V5-V500R020C10SPC212/firmware-HG8145V5-V500R020C10SPC212/web/frame_Arabic

11. frame_huawei
   Descripción: Interfaz web estándar Huawei (192.168.100.1)
   Ruta: /home/runner/work/firmware-HG8145V5-V500R020C10SPC212/firmware-HG8145V5-V500R020C10SPC212/web/frame_huawei

12. AllUsers
   Descripción: Recursos compartidos todas las interfaces
   Ruta: /home/runner/work/firmware-HG8145V5-V500R020C10SPC212/firmware-HG8145V5-V500R020C10SPC212/web/AllUsers

13. frame_argentina
   Descripción: Interfaz Argentina
   Ruta: /home/runner/work/firmware-HG8145V5-V500R020C10SPC212/firmware-HG8145V5-V500R020C10SPC212/web/frame_argentina

14. frame_zain
   Descripción: Interfaz Zain
   Ruta: /home/runner/work/firmware-HG8145V5-V500R020C10SPC212/firmware-HG8145V5-V500R020C10SPC212/web/frame_zain

15. frame_qtel
   Descripción: Interfaz Qtel Qatar
   Ruta: /home/runner/work/firmware-HG8145V5-V500R020C10SPC212/firmware-HG8145V5-V500R020C10SPC212/web/frame_qtel

NOTA: Todas estas interfaces escuchan en los mismos puertos,
la interfaz activa depende de la configuración del ISP en hw_ctree.xml

## 2. PUERTOS Y SERVICIOS
--------------------------------------------------------------------------------

Puertos TCP/UDP utilizados por el dispositivo:

  • FTP Pasivo                     Rango: 12000-12100 (TCP)
  • FTP                            Puerto: 21 (TCP)
  • SSH                            Puerto: 22 (TCP)
  • Telnet                         Puerto: 23 (TCP)
  • HTTPS Web                      Puerto: 443 (TCP)
  • HTTPS Web                      Puerto: 7017 (TCP)
  • TR-069 CWMP Server             Puerto: 7547 (TCP)
  • TR-069 CWMP                    Puerto: 7547 (TCP)
  • HTTP Web                       Puerto: 80 (TCP)
  • HTTP Web (Externa)             Puerto: 80 (TCP)

ACCESO A LAS INTERFACES:
  • HTTP:  http://192.168.100.1:80
  • HTTPS: https://192.168.100.1:443
  • HTTPS: https://192.168.100.1:7017  (Qatar/algunas variantes)

CREDENCIALES DEFAULT:
  • Usuario: admin / Password: admin
  • Usuario: telecomadmin / Password: admintelecom
  • El password puede variar según ISP

## 3. MÉTODOS DE ACTIVACIÓN MODO DEBUG/ENGINEER/DEVELOPER
--------------------------------------------------------------------------------

### MÉTODO 1: Modificación de configuración
Tipo: SOFTWARE | Dificultad: AVANZADO

Descripción: Descifrar y modificar hw_ctree.xml

Pasos:
  1. Extraer firmware con HuaweiFirmwareTool
  2. Descifrar hw_ctree.xml usando aescrypt2 en chroot
  3. Modificar parámetros X_HW_DEBUG:
     - TelnetSwitch: 0 → 1 (activar Telnet)
     - SshSwitch: 0 → 1 (activar SSH)
  4. Re-cifrar y flashear firmware modificado
  5. Acceder via telnet 192.168.100.1 puerto 23
  6. Usuario: root (password del admin web)

XPaths en hw_ctree.xml:
  - /configuration/InternetGatewayDevice/X_HW_DEBUG/TelnetSwitch
  - /configuration/InternetGatewayDevice/X_HW_DEBUG/SshSwitch

--------------------------------------------------------------------------------

### MÉTODO 2: Páginas web ocultas X_HW_DEBUG
Tipo: SOFTWARE | Dificultad: MEDIO

Descripción: Acceder a páginas de diagnóstico ocultas

Pasos:
  1. Iniciar sesión como telecomadmin (nivel 2)
  2. Acceder a URLs ocultas:
     - http://192.168.100.1/html/X_HW_DEBUG.asp
     - Buscar en web/FrameAISAP/index.asp referencias X_HW_DEBUG
  3. Características disponibles:
     - AMP.Optic: Diagnóstico óptico (RxPower, TxPower)
     - SMP.DM.ResetBoard: Reset del dispositivo
     - AccessModeDisp: Modo de acceso PON/EPON
     - GetOptTxMode: Modo TX óptico

--------------------------------------------------------------------------------

### MÉTODO 3: Comandos CLI ocultos
Tipo: SOFTWARE | Dificultad: MEDIO

Descripción: Comandos de debug via telnet/SSH

Pasos:
  1. Habilitar telnet/SSH (ver método 1)
  2. Conectar: telnet 192.168.100.1
  3. Login: root / <password_admin>
  4. Comandos útiles:
     - display access mode
     - get optic txmode
     - set wlan enable laninst 1 enable 1
     - load pack by tftp/ftp/https (upgrade)
     - debugging <subsystem>

Comandos CLI útiles:
  $ display access mode
  $ get optic txmode
  $ display 8021x status
  $ debugging dsp diagnose
  $ capture start mode all

--------------------------------------------------------------------------------

### MÉTODO 4: Combinación de botón Reset
Tipo: HARDWARE | Dificultad: FÁCIL

Descripción: Reset a valores de fábrica

Pasos:
  1. Con el ONT encendido
  2. Mantener botón RESET presionado 10 segundos
  3. El ONT se reiniciará con configuración de fábrica
  4. Credenciales default:
     - Usuario: admin / telecomadmin
     - Password: admin / admintelecom (varía según ISP)
  Nota: keyconfig.xml define InvalidCount=4 para HG8245C

--------------------------------------------------------------------------------

### MÉTODO 5: Botón WPS/WiFi
Tipo: HARDWARE | Dificultad: FÁCIL

Descripción: Activar WPS pairing

Pasos:
  1. Presionar botón WPS/WiFi 2-3 segundos
  2. LED WPS parpadeará por 2 minutos
  3. Modo WPS-PBC activo para conectar dispositivos
  4. Mantener presionado >10s puede activar WiFi On/Off

--------------------------------------------------------------------------------

### MÉTODO 6: Puerto Serial UART
Tipo: HARDWARE | Dificultad: EXPERTO

Descripción: Acceso bootloader via UART

Pasos:
  1. Abrir el ONT (anula garantía)
  2. Localizar pads UART (TX, RX, GND)
  3. Conectar adaptador USB-TTL 3.3V
  4. Configuración: 115200 8N1
  5. Acceso a U-Boot al encender
  6. Comandos U-Boot para modificar variables de entorno

⚠️  ADVERTENCIA: ¡PUEDE BRICKEAR EL DISPOSITIVO!

--------------------------------------------------------------------------------

## 4. COMANDOS CLI IMPORTANTES (vía Telnet/SSH)
--------------------------------------------------------------------------------

### Info:
  $ display speed test result
  $ display macaddress
  $ display rf config
  $ display optic
  $ display poncnt upstatistic
  $ display poncnt dnstatistic
  $ display poncnt gemport upstatistic
  $ display access mode
  $ display port mac num
  $ display wifichip

### Debug:
  $ set udm debug
  $ set voicedebug
  $ set voip dtmfdebug" ObjPath="InternetGatewayDevice.X_HW_DEBUG.VSPA.SetVoipDtmfDiag" OpType="0" Help="set voip dtmfdebug switch {[0:disable, 1:enable]} printlevel {[0,2]} autostop {[10,720]}
  $ set sec debug" ObjPath="InternetGatewayDevice.X_HW_DEBUG.BBSP.SecCli" OpType="0" Help="set sec debug [int]
  $ set cwmp debug
  $ debugging dsp t38diag
  $ debugging dsp record
  $ debugging dsp diagnose
  $ debugging dsp para diagnose
  $ debugging voip signaling

### Get:
  $ get wlan enable
  $ get wlan basic
  $ get wlan stats
  $ get wlan advance
  $ get wlan associated
  $ get speed test
  $ get wlan wps
  $ get port config
  $ get port config all
  $ get global hgdetect

### Upgrade:
  $ load pack

## 5. BINARIOS CLAVE PARA ANÁLISIS
--------------------------------------------------------------------------------

• web
  Tipo: ELF ARM
  Tamaño: 349,876 bytes
  Descripción: Servidor web principal (Boa/lighttpd)
  Ruta: /home/runner/work/firmware-HG8145V5-V500R020C10SPC212/firmware-HG8145V5-V500R020C10SPC212/bin/web

• cfgtool
  Tipo: ELF ARM
  Tamaño: 13,920 bytes
  Descripción: Herramienta de gestión de configuración
  Ruta: /home/runner/work/firmware-HG8145V5-V500R020C10SPC212/firmware-HG8145V5-V500R020C10SPC212/bin/cfgtool

• aescrypt2
  Tipo: ELF ARM
  Tamaño: 17,692 bytes
  Descripción: Cifrado/descifrado AES-256-CBC para hw_ctree.xml
  Ruta: /home/runner/work/firmware-HG8145V5-V500R020C10SPC212/firmware-HG8145V5-V500R020C10SPC212/bin/aescrypt2

• clid
  Tipo: ELF ARM
  Tamaño: 183,008 bytes
  Descripción: Demonio CLI (telnet/SSH)
  Ruta: /home/runner/work/firmware-HG8145V5-V500R020C10SPC212/firmware-HG8145V5-V500R020C10SPC212/bin/clid

Para análisis con Capstone:
  $ python tools/arm_disasm.py bin/<binary>

Para análisis con radare2:
  $ r2 -A bin/<binary>
  [0x00000000]> aaa    # Analizar
  [0x00000000]> afl    # Listar funciones
  [0x00000000]> pdf @sym.main  # Desensamblar main

## 6. RESUMEN Y RECOMENDACIONES
--------------------------------------------------------------------------------

OPCIÓN MÁS FÁCIL (Sin modificar firmware):
  1. Probar credenciales default: admin/admin, telecomadmin/admintelecom
  2. Buscar páginas web ocultas en /html/X_HW_DEBUG.asp
  3. Revisar nivel de usuario (0=básico, 1=normal, 2=admin)

OPCIÓN INTERMEDIA (Requiere acceso web admin):
  1. Usar mitmproxy para interceptar y modificar UserLevel a 2
  2. Acceder a características X_HW_DEBUG ocultas
  3. Ver repositorio: huawei_proxy/proxy.py

OPCIÓN AVANZADA (Requiere flasheo firmware):
  1. Extraer firmware con HuaweiFirmwareTool
  2. Descifrar hw_ctree.xml con aescrypt2 en chroot qemu-arm
  3. Modificar TelnetSwitch/SshSwitch a 1
  4. Re-cifrar y flashear
  5. Acceso completo via telnet/SSH

OPCIÓN EXPERTO (Requiere hardware):
  1. Soldar cables a pads UART internos
  2. Acceso a U-Boot bootloader
  3. Modificar variables de entorno
  ⚠️  Riesgo de brick permanente

================================================================================
Análisis generado por firmware_analysis.py
Repositorio: Uaemextop/firmware-HG8145V5-V500R020C10SPC212
================================================================================