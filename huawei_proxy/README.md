# Huawei ONT Traffic Interceptor Proxy

Proxy MITM (Man-in-the-Middle) para interceptar y modificar el tráfico del router Huawei HG8145V5 en 192.168.100.1 para desbloquear funciones ocultas y privilegios de administrador.

## Características

- **Interceptación SSL/TLS**: Captura tráfico HTTPS mediante certificado CA personalizado
- **Elevación de privilegios**: Modifica automáticamente el UserLevel a nivel administrador (2)
- **Desbloqueo de funciones ocultas**:
  - Telnet/SSH switches
  - Funciones X_HW_DEBUG
  - Menús ocultos en la interfaz web
  - Opciones avanzadas deshabilitadas
- **Captura de tráfico**: Registra todas las peticiones/respuestas en `captured_traffic/`
- **Integración con Chrome**: Script PowerShell para configurar perfil de Chrome automáticamente

## Análisis del Firmware

Este proxy está diseñado específicamente para el firmware HG8145V5-V500R020C10SPC212. Los análisis muestran:

### Niveles de Usuario
- **UserLevel 0**: Usuario básico (acceso limitado)
- **UserLevel 1**: Usuario normal (más funciones)
- **UserLevel 2**: Administrador (telecomadmin) - **acceso completo**

### Funciones Ocultas Identificadas
1. **X_HW_DEBUG.TelnetSwitch**: Habilita acceso Telnet
2. **X_HW_DEBUG.SshSwitch**: Habilita acceso SSH
3. **X_HW_DEBUG.AMP.OntOnlineStatus**: Estado avanzado del ONT
4. **X_HW_DEBUG.SMP.DM.ResetBoard**: Funciones de reset avanzado

### Archivos Web Relevantes
- `web/frame_huawei/login.asp`: Página de login con verificación de UserLevel
- `web/frame_huawei/menuList.asp`: Estructura de menús con elementos ocultos
- `web/menu/*.xml`: Configuración de visibilidad de menús por ISP

## Requisitos

- Windows 11
- Python 3.8+
- Google Chrome
- Privilegios de administrador (para instalación de certificado)

## Instalación

### 1. Instalar dependencias de Python

```bash
cd huawei_proxy
pip install -r requirements.txt
```

### 2. Generar certificado SSL

```bash
python generate_cert.py
```

Esto creará los archivos en `certs/`:
- `mitmproxy-ca-cert.pem` (certificado)
- `mitmproxy-ca-cert.key` (clave privada)
- `mitmproxy-ca-cert.cer` (formato Windows)

### 3. Instalar certificado en Windows (como Administrador)

```powershell
powershell -ExecutionPolicy Bypass -File install_cert.ps1
```

**IMPORTANTE**: Debes ejecutar PowerShell como Administrador para esta operación.

### 4. Configurar perfil de Chrome con proxy

```powershell
powershell -ExecutionPolicy Bypass -File setup_chrome_profile.ps1
```

Esto creará un perfil de Chrome llamado "Huawei-Proxy" configurado automáticamente para usar el proxy.

## Uso

### Iniciar el Proxy

```bash
python start_proxy.py
```

Opciones:
- `-p, --port`: Puerto del proxy (default: 8080)
- `-q, --quiet`: Modo silencioso (menos verboso)

Ejemplo:
```bash
python start_proxy.py -p 8080
```

### Usar Chrome con el Proxy

Opción 1 - Automático (después de ejecutar setup_chrome_profile.ps1):
```powershell
"C:\Program Files\Google\Chrome\Application\chrome.exe" --user-data-dir="%LOCALAPPDATA%\Google\Chrome\User Data" --profile-directory="Huawei-Proxy" http://192.168.100.1
```

Opción 2 - Manual:
1. Abre Chrome
2. Configuración → Sistema → Abrir configuración del proxy
3. Configuración manual:
   - HTTP Proxy: 127.0.0.1:8080
   - HTTPS Proxy: 127.0.0.1:8080
4. Navega a http://192.168.100.1

### Acceder al Router

1. Navega a `http://192.168.100.1` en el Chrome configurado
2. El proxy interceptará y modificará el tráfico automáticamente:
   - Elevará tu UserLevel a administrador (2)
   - Desbloqueará funciones ocultas de Telnet/SSH
   - Mostrará menús y opciones ocultas
   - Habilitará funciones X_HW_DEBUG
3. Verás logs en la consola del proxy
4. Todo el tráfico se guardará en `captured_traffic/`

## Funcionalidad del Proxy

### Modificaciones en Requests (Peticiones)

1. **Login requests**: Añade headers de admin override
2. **API calls** (set.cgi, get.cgi): Eleva UserLevel a 2
3. **Config changes**: Permite modificaciones de admin

### Modificaciones en Responses (Respuestas)

1. **JavaScript/HTML**:
   - Cambia `var Userlevel = 0;` → `var Userlevel = 2;`
   - Cambia `display:none` → `display:block` en elementos de debug/telnet/ssh
   - Remueve atributos `disabled="disabled"` de inputs
   - Muestra menús ocultos

2. **JSON**:
   - Modifica `"UserLevel":"0"` → `"UserLevel":"2"`
   - Activa `"TelnetSwitch":"1"` y `"SshSwitch":"1"`
   - Habilita funciones X_HW_DEBUG

### Captura de Tráfico

Todos los requests y responses se guardan en `captured_traffic/`:
- `request_YYYYMMDD_HHMMSS_ffffff.txt`: Peticiones HTTP
- `response_YYYYMMDD_HHMMSS_ffffff.txt`: Respuestas HTTP

Formato de logs:
```
Timestamp: 20260227_124523_123456
Method: POST
URL: http://192.168.100.1/asp/GetRandCount.asp
Host: 192.168.100.1
Path: /asp/GetRandCount.asp

Headers:
  Content-Type: application/x-www-form-urlencoded
  ...

Body:
RequestFile=html/index.html&...
```

## Estructura del Proyecto

```
huawei_proxy/
├── proxy.py                      # Interceptor principal de mitmproxy
├── start_proxy.py                # Script para iniciar el proxy
├── generate_cert.py              # Generador de certificado CA
├── install_cert.ps1              # Instalador de certificado (PowerShell)
├── setup_chrome_profile.ps1      # Configurador de Chrome (PowerShell)
├── requirements.txt              # Dependencias Python
├── README.md                     # Esta documentación
├── certs/                        # Certificados generados
│   ├── mitmproxy-ca-cert.pem
│   ├── mitmproxy-ca-cert.key
│   └── mitmproxy-ca-cert.cer
└── captured_traffic/             # Tráfico capturado
    ├── request_*.txt
    └── response_*.txt
```

## Configuración ISP: Megacable

El firmware incluye múltiples configuraciones ISP en `web/menu/`. Para Megacable (México), el proxy modificará:

1. **Credenciales default**:
   - Usuario: `admin` o `telecomadmin`
   - El proxy eleva privilegios independientemente del usuario

2. **Funciones específicas de Megacable**:
   - Desbloqueo de configuración WAN
   - Acceso a ONT status avanzado
   - Configuración de VLAN
   - Parámetros TR-069 (ACS)

## Seguridad

⚠️ **ADVERTENCIAS IMPORTANTES**:

1. Este proxy es para uso educativo y análisis de tu propio equipo
2. Solo úsalo en routers de tu propiedad o con autorización
3. Modificar la configuración del router puede afectar tu servicio de internet
4. El certificado CA da acceso completo a interceptar tráfico SSL
5. **NO** compartas el certificado CA con nadie
6. Desinstala el certificado después de usarlo:
   ```powershell
   # Abrir certmgr.msc → Trusted Root Certification Authorities → Certificates
   # Buscar "Huawei ONT Interceptor Root CA" y eliminar
   ```

## Troubleshooting

### El proxy no intercepta tráfico HTTPS
- Verifica que el certificado esté instalado: `certmgr.msc` → Trusted Root Certification Authorities
- Reinicia Chrome después de instalar el certificado
- Asegúrate de usar el perfil de Chrome configurado

### Chrome muestra error de certificado
- El certificado no está instalado correctamente
- Ejecuta `install_cert.ps1` como Administrador nuevamente

### No se muestran las opciones ocultas
- Verifica que el proxy esté interceptando tráfico (logs en consola)
- Limpia caché del navegador (Ctrl+Shift+Del)
- Asegúrate de que las modificaciones se estén aplicando (logs con `[MODIFY]`)

### El router no responde después de cambios
- Resetea el router desde el botón físico (10 segundos)
- Restaura configuración de fábrica si es necesario

## Funciones Avanzadas

### Analizar tráfico capturado

Los archivos en `captured_traffic/` contienen todas las peticiones/respuestas. Puedes:

1. **Buscar credenciales**:
```bash
grep -r "password\|passwd" captured_traffic/
```

2. **Analizar configuración**:
```bash
grep -r "X_HW_DEBUG\|TelnetSwitch" captured_traffic/
```

3. **Encontrar endpoints API**:
```bash
grep "URL:" captured_traffic/request_*.txt | sort -u
```

### Modificar reglas del proxy

Edita `proxy.py` para añadir tus propias reglas de modificación:

```python
def _modify_response(self, flow: http.HTTPFlow) -> None:
    if "tu_patron" in response_text:
        response_text = response_text.replace("valor_antiguo", "valor_nuevo")
        flow.response.text = response_text
```

## Referencias

- Firmware: HG8145V5-V500R020C10SPC212
- Hardware: HiSilicon ARM Cortex-A9
- Interfaz web: `/web/frame_huawei/`
- Binarios clave:
  - `/bin/aescrypt2`: Encriptación de configuración
  - `/lib/libhw_ssp_basic.so`: Funciones de seguridad
  - `/bin/cfgtool`: Gestión de configuración

## Créditos

- Firmware extraído con [HuaweiFirmwareTool](https://github.com/Uaemextop/HuaweiFirmwareTool)
- Proxy basado en [mitmproxy](https://mitmproxy.org/)
- Análisis de firmware del repositorio Uaemextop/firmware-HG8145V5-V500R020C10SPC212

## Licencia

Este proyecto es solo para fines educativos y de investigación. Úsalo de manera responsable.
