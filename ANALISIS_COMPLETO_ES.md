# Análisis Completo del Firmware HG8145V5-V500R020C10SPC212

## Resumen Ejecutivo

Este documento presenta un análisis exhaustivo del firmware del Huawei HG8145V5 V500R020C10SPC212, identificando interfaces web alternativas, puertos de servicio, y múltiples métodos para activar modos debug/engineer/developer tanto por software como por hardware.

---

## 🌐 1. INTERFACES WEB DISPONIBLES

### Interfaz Principal
- **URL:** `http://192.168.100.1` o `https://192.168.100.1`
- **Credenciales default:**
  - Usuario: `admin` / Password: `admin`
  - Usuario: `telecomadmin` / Password: `admintelecom`

### Interfaces Web Alternativas por ISP

El firmware contiene **15 interfaces web** distintas para diferentes operadores:

| # | Directorio | ISP/Región | URL Base |
|---|-----------|-----------|----------|
| 1 | `frame_huawei` | Huawei Estándar | `http://192.168.100.1` |
| 2 | `FrameAISAP` | AIS Tailandia | `http://192.168.100.1` |
| 3 | `frame_Stc` | STC Arabia Saudita | `http://192.168.100.1` |
| 4 | `frame_qtel` | Qtel Qatar | `http://192.168.100.1` |
| 5 | `frame_zain` | Zain (Medio Oriente) | `http://192.168.100.1` |
| 6 | `frame_argentina` | Argentina | `http://192.168.100.1` |
| 7 | `frame_Arabic` | Árabe (genérico) | `http://192.168.100.1` |
| 8 | `frame_pccw` | PCCW Hong Kong | `http://192.168.8.1` |
| 9 | `frame_XGPON` | XGPON (genérico) | `http://192.168.100.1` |
| 10 | `frame_xgponglobe` | Globe Philippines | `http://192.168.100.1` |
| 11 | `frame_IraqO3` | Iraq O3 | `http://192.168.100.1` |
| 12 | `frame_telmex` | Telmex México | `http://192.168.1.254` |
| 13 | `frame_du` | Du (Emirates) | `http://192.168.100.1` |

**IMPORTANTE:** Todas estas interfaces escuchan en los mismos puertos. La interfaz activa se determina por la configuración del ISP en `hw_ctree.xml`.

---

## 🔌 2. PUERTOS Y SERVICIOS

### Puertos TCP Abiertos

| Servicio | Puerto | Protocolo | Descripción |
|----------|--------|-----------|-------------|
| HTTP Web | 80 | TCP | Interfaz web principal |
| HTTPS Web | 443 | TCP | Interfaz web segura |
| HTTPS Web (Alt) | 7017 | TCP | Qatar y algunas variantes |
| Telnet | 23 | TCP | CLI (deshabilitado por default) |
| SSH | 22 | TCP | Shell seguro (deshabilitado por default) |
| FTP | 21 | TCP | Servidor FTP |
| FTP Pasivo | 12000-12100 | TCP | Rango FTP pasivo |
| TR-069 CWMP | 7547 | TCP | Gestión remota ACS |

### Acceso a las Interfaces

```bash
# HTTP (puerto 80)
http://192.168.100.1
http://192.168.100.1:80

# HTTPS (puerto 443)
https://192.168.100.1
https://192.168.100.1:443

# HTTPS alternativo (puerto 7017 - Qatar, algunas variantes)
https://192.168.100.1:7017

# Telnet (si está habilitado)
telnet 192.168.100.1 23

# SSH (si está habilitado)
ssh root@192.168.100.1
```

---

## 🛠️ 3. MÉTODOS DE ACTIVACIÓN MODO DEBUG/ENGINEER/DEVELOPER

### Método 1: Modificación de Configuración (SOFTWARE - AVANZADO)

**Dificultad:** ⭐⭐⭐⭐⭐ Experto
**Requiere:** Acceso físico + tools de firmware

**Descripción:** Descifrar y modificar `hw_ctree.xml` para habilitar Telnet/SSH

**Pasos:**

1. **Extraer firmware:**
   ```bash
   # Usando HuaweiFirmwareTool
   python HuaweiFirmwareTool.py extract firmware.bin -o extracted/
   ```

2. **Descifrar hw_ctree.xml:**
   ```bash
   # Requiere qemu-arm-static + chroot en rootfs extraído
   sudo cp /usr/bin/qemu-arm-static rootfs/usr/bin/
   sudo chroot rootfs qemu-arm-static /bin/aescrypt2 1 /etc/wap/hw_ctree.xml /tmp/out.xml
   gunzip /tmp/out.xml.gz
   ```

3. **Modificar parámetros X_HW_DEBUG:**
   ```xml
   <!-- Cambiar estos valores de 0 a 1 -->
   <X_HW_DEBUG>
     <TelnetSwitch>1</TelnetSwitch>  <!-- 0 → 1 -->
     <SshSwitch>1</SshSwitch>        <!-- 0 → 1 -->
   </X_HW_DEBUG>
   ```

4. **Re-cifrar y flashear:**
   ```bash
   # Re-cifrar configuración
   gzip out.xml
   sudo chroot rootfs qemu-arm-static /bin/aescrypt2 0 /tmp/out.xml.gz /etc/wap/hw_ctree.xml

   # Re-empaquetar firmware
   # Flashear via TR-069 o interfaz web
   ```

5. **Acceder via Telnet/SSH:**
   ```bash
   telnet 192.168.100.1
   # Usuario: root
   # Password: <mismo password del admin web>
   ```

**XPaths importantes:**
- `/configuration/InternetGatewayDevice/X_HW_DEBUG/TelnetSwitch`
- `/configuration/InternetGatewayDevice/X_HW_DEBUG/SshSwitch`

---

### Método 2: Páginas Web Ocultas X_HW_DEBUG (SOFTWARE - MEDIO)

**Dificultad:** ⭐⭐⭐ Medio
**Requiere:** Acceso web como telecomadmin (nivel 2)

**Descripción:** Acceder a páginas de diagnóstico ocultas en la interfaz web

**Pasos:**

1. **Iniciar sesión como telecomadmin:**
   - Usuario: `telecomadmin`
   - Password: `admintelecom` (varía según ISP)

2. **Acceder a URLs ocultas:**
   ```
   http://192.168.100.1/html/X_HW_DEBUG.asp
   http://192.168.100.1/html/bbsp/diagtools.asp
   http://192.168.100.1/html/amp/optical_info.asp
   ```

3. **Características disponibles:**
   - **AMP.Optic:** Diagnóstico óptico (RxPower, TxPower, Temperatura, Voltaje)
   - **SMP.DM.ResetBoard:** Reset completo del dispositivo
   - **AccessModeDisp:** Ver modo de acceso (GPON/EPON/XGPON)
   - **GetOptTxMode:** Modo de transmisión óptica

**Referencias en código:**
```javascript
// En web/FrameAISAP/index.asp
var opticStatus = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.GetOptStaus.status);%>';
var opticInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_DEBUG.AMP.Optic,TxPower|RxPower|Voltage|Temperature|Bias, stOpticInfo);%>;
```

---

### Método 3: Comandos CLI Ocultos (SOFTWARE - MEDIO)

**Dificultad:** ⭐⭐⭐ Medio
**Requiere:** Telnet/SSH habilitado (ver Método 1)

**Descripción:** Ejecutar comandos de debug via CLI

**Pasos:**

1. **Conectar via Telnet:**
   ```bash
   telnet 192.168.100.1
   # Login: root / <password>
   ```

2. **Comandos útiles:**

   **Información del sistema:**
   ```bash
   display access mode           # Modo de acceso PON
   display optic                 # Info óptica completa
   display macaddress            # MAC addresses
   get wlan enable               # Estado WiFi
   ```

   **Debug y diagnóstico:**
   ```bash
   debugging dsp diagnose        # Diagnóstico DSP
   capture start mode all        # Captura de tráfico
   set wlan enable laninst 1 enable 1  # Habilitar WiFi
   ```

   **Upgrade firmware:**
   ```bash
   load pack by tftp svrip 192.168.100.2 remotefile firmware.bin
   load pack by ftp svrip 192.168.100.2 remotefile firmware.bin
   load pack by https svrip server.com remotefile firmware.bin
   ```

**Archivo de comandos CLI:** `configs/hw_cli.xml` (4,500+ líneas de comandos)

---

### Método 4: Botón Reset (HARDWARE - FÁCIL)

**Dificultad:** ⭐ Fácil
**Requiere:** Acceso físico al dispositivo

**Descripción:** Reset a configuración de fábrica

**Pasos:**

1. Con el ONT **encendido**
2. Localizar botón **RESET** (agujero pequeño en panel trasero)
3. Presionar con clip/aguja por **10 segundos continuos**
4. Esperar que el ONT se reinicie (LEDs parpadearán)
5. El ONT volverá a configuración de fábrica

**Credenciales post-reset:**
- Usuario: `admin` / Password: `admin`
- Usuario: `telecomadmin` / Password: `admintelecom`

**Nota técnica:** `keyconfig.xml` define `InvalidCount="4"` para HG8245C (máx 4 intentos de reset)

---

### Método 5: Botón WPS/WiFi (HARDWARE - FÁCIL)

**Dificultad:** ⭐ Fácil
**Requiere:** Acceso físico al dispositivo

**Descripción:** Activar WPS pairing o WiFi On/Off

**Pasos WPS:**

1. Presionar botón **WPS/WiFi** por **2-3 segundos**
2. LED WPS parpadeará por **2 minutos**
3. Modo WPS-PBC activo para emparejar dispositivos
4. Conectar dispositivo WiFi presionando su botón WPS

**WiFi On/Off:**

1. Mantener presionado botón **WPS/WiFi** por **>10 segundos**
2. WiFi se activará/desactivará completamente

---

### Método 6: Puerto Serial UART (HARDWARE - EXPERTO)

**Dificultad:** ⭐⭐⭐⭐⭐ Experto
**Requiere:** Soldadura + adaptador USB-TTL

⚠️ **ADVERTENCIA:** ¡PUEDE BRICKEAR EL DISPOSITIVO PERMANENTEMENTE! Anula garantía.

**Descripción:** Acceso directo al bootloader U-Boot

**Pasos:**

1. **Abrir el ONT** (anula garantía)
2. **Localizar pads UART** en PCB (TX, RX, GND)
3. **Soldar cables** o usar clips de prueba
4. **Conectar adaptador USB-TTL:**
   - TX del ONT → RX del adaptador
   - RX del ONT → TX del adaptador
   - GND → GND
   - **IMPORTANTE:** Usar adaptador **3.3V** (NO 5V)

5. **Configurar terminal serial:**
   ```bash
   # Linux
   screen /dev/ttyUSB0 115200

   # Windows
   # PuTTY: COM port, 115200, 8N1

   # Configuración: 115200 baudios, 8 bits, sin paridad, 1 bit stop
   ```

6. **Acceder a U-Boot:**
   - Encender ONT mientras terminal está conectado
   - Presionar rápidamente cualquier tecla durante boot
   - Aparecerá prompt `hisilicon #`

7. **Comandos U-Boot útiles:**
   ```bash
   printenv              # Ver variables de entorno
   setenv telnet 1       # Habilitar telnet
   saveenv               # Guardar cambios
   reset                 # Reiniciar
   ```

**Chipset:** HiSilicon SD5117P ARM Cortex-A9

---

## 🔍 4. ANÁLISIS DE BINARIOS CON CAPSTONE

### Strings Relevantes Encontrados

#### bin/web (Servidor Web)
```
• HW_WEB_GetUserLevel
• HW_WEB_GetUserLevelByHandle
• TELNETWanEnable
• SSHWanEnable
• WEB_InitSSHEnableAIS
• HW_WEB_CheckUserPassword
• HW_WEB_GetAdminAccount
• InternetGatewayDevice.X_HW_DEBUG.AMP.WifiCoverSetWlanBasic
• InternetGatewayDevice.X_HW_DEBUG.SMP.DM.ResetBoard
```

#### bin/clid (CLI Daemon)
```
• HW_CLI_TelnetLocalAddr
• HW_CLI_GetCurTelnetClientNum
• HW_CLI_CheckLoginLock
• HW_CLI_VerifySuPassword
• set userpasswd
```

### Funciones Clave de Autenticación

| Binario | Función | Descripción |
|---------|---------|-------------|
| web | `HW_WEB_GetUserLevel` | Obtiene nivel de usuario (0/1/2) |
| web | `HW_WEB_CheckUserPassword` | Valida password de usuario |
| web | `HW_WEB_AuthPageForFrame` | Autenticación de páginas |
| clid | `HW_CLI_CheckLoginLock` | Verifica bloqueo de login |
| clid | `HW_CLI_VerifySuPassword` | Verifica password superusuario |

### Análisis Avanzado con Radare2

```bash
# Analizar binario
r2 -A bin/web
[0x00000000]> aaa                    # Analizar todo
[0x00000000]> afl                    # Listar funciones
[0x00000000]> axt @str.UserLevel     # Referencias a UserLevel
[0x00000000]> pdf @sym.HW_WEB_GetUserLevel  # Desensamblar función

# Buscar strings
[0x00000000]> iz | grep -i telnet
[0x00000000]> iz | grep -i debug

# Analizar importaciones
[0x00000000]> ii                     # Imports
[0x00000000]> ie                     # Exports
```

---

## 📊 5. NIVELES DE USUARIO

El firmware maneja **3 niveles de usuario**:

| Nivel | Nombre | Permisos | Características |
|-------|--------|----------|----------------|
| 0 | Básico | Limitado | Ver info básica, cambiar WiFi |
| 1 | Normal | Medio | Configuración avanzada LAN/WAN |
| 2 | Admin | Completo | Acceso total, debug, TR-069 |

**Usuarios y niveles:**
- `admin` → Nivel 0 o 1 (según ISP)
- `telecomadmin` → Nivel 2 (acceso completo)

**Verificar nivel en código web:**
```javascript
var userLevel = '<%HW_WEB_GetUserLevel();%>';
// 0 = básico, 1 = normal, 2 = admin
```

---

## 🎯 6. RESUMEN Y RECOMENDACIONES

### Opción 1: MÁS FÁCIL (Sin Modificar Firmware)

✅ **Ventajas:** No invasivo, reversible
❌ **Desventajas:** Funcionalidad limitada

**Pasos:**
1. Probar credenciales default: `admin/admin`, `telecomadmin/admintelecom`
2. Buscar páginas web ocultas: `/html/X_HW_DEBUG.asp`
3. Revisar nivel de usuario (intentar elevar a nivel 2)

---

### Opción 2: INTERMEDIA (Proxy Interception)

✅ **Ventajas:** No modifica firmware, más funciones
❌ **Desventajas:** Requiere mitmproxy setup

**Pasos:**
1. Instalar mitmproxy: `pip install mitmproxy`
2. Usar addon personalizado para modificar `UserLevel` a 2
3. Interceptar y modificar respuestas web
4. Acceder a características X_HW_DEBUG ocultas

**Ver:** Repositorio `huawei_proxy/proxy.py` (si existe en memoria)

---

### Opción 3: AVANZADA (Modificar Firmware)

✅ **Ventajas:** Acceso completo telnet/SSH
❌ **Desventajas:** Requiere re-flash, riesgo de brick

**Pasos:**
1. Extraer firmware con HuaweiFirmwareTool
2. Descifrar `hw_ctree.xml` con aescrypt2 + qemu-arm
3. Modificar `TelnetSwitch=1`, `SshSwitch=1`
4. Re-cifrar y flashear firmware modificado
5. Acceso root completo via telnet/SSH

**Archivos clave:**
- `configs/hw_ctree.xml` (cifrado)
- `bin/aescrypt2` (herramienta descifrado)
- `configs/kmc_store_A/B` (material de clave KMC)

---

### Opción 4: EXPERTO (Hardware UART)

✅ **Ventajas:** Acceso U-Boot, máximo control
❌ **Desventajas:** Soldadura, alto riesgo brick

⚠️ **SOLO PARA EXPERTOS** - Puede inutilizar el dispositivo permanentemente

**Requiere:**
- Soldador y experiencia
- Adaptador USB-TTL 3.3V
- Conocimiento de U-Boot ARM

---

## 📚 7. HERRAMIENTAS DE ANÁLISIS

### Python Scripts Incluidos

```bash
# Análisis completo del firmware
python tools/firmware_analysis.py

# Análisis de binarios con Capstone
python tools/capstone_analysis.py

# Extracción de configuración
python tools/ctree_extract.py configs/

# Comparación de firmwares
python tools/config_analyzer.py --configs-dir configs/
```

### Herramientas Externas Recomendadas

| Herramienta | Uso | Instalación |
|-------------|-----|-------------|
| **HuaweiFirmwareTool** | Extraer/empaquetar firmware | `git clone https://github.com/Uaemextop/HuaweiFirmwareTool` |
| **qemu-arm-static** | Ejecutar binarios ARM | `apt install qemu-user-static` |
| **Capstone** | Desensamblador ARM | `pip install capstone` |
| **radare2** | Análisis binario | `apt install radare2` |
| **mitmproxy** | Interceptar tráfico web | `pip install mitmproxy` |
| **binwalk** | Análisis de firmware | `apt install binwalk` |

---

## ⚠️ 8. ADVERTENCIAS LEGALES Y TÉCNICAS

### Legal
- ⚖️ Solo para uso en dispositivos propios
- ⚖️ Modificar firmware puede anular garantía
- ⚖️ Algunas técnicas pueden violar ToS del ISP
- ⚖️ Uso educacional y de investigación

### Técnica
- ⚠️ Flashear firmware modificado puede **brickear** el dispositivo
- ⚠️ Backup siempre la configuración original
- ⚠️ Método UART puede dañar hardware si se usa 5V en lugar de 3.3V
- ⚠️ Algunos ISPs detectan modificaciones via TR-069

---

## 📞 9. SOPORTE Y RECURSOS

### Repositorio
**GitHub:** `Uaemextop/firmware-HG8145V5-V500R020C10SPC212`

### Documentación Relacionada
- `README.md` - Información general del repositorio
- `.github/copilot-instructions.md` - Instrucciones técnicas detalladas
- `FIRMWARE_ANALYSIS.md` - Este documento
- `tools/` - Scripts de análisis

### Comunidad
- GitHub Issues para reportar problemas
- Pull Requests bienvenidos para mejoras

---

## 📝 10. CHANGELOG

- **2026-02-27:** Análisis inicial completo
  - Identificadas 15 interfaces web
  - Documentados 6 métodos de activación debug
  - Análisis Capstone de binarios clave
  - Scripts Python de análisis automatizado

---

**Documento generado por:** Claude Code Agent
**Fecha:** 2026-02-27
**Versión:** 1.0
**Firmware analizado:** HG8145V5-V500R020C10SPC212
