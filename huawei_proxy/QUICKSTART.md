# Huawei ONT Proxy - Quick Start Guide

## Windows 11 - Inicio Rápido

### Paso 1: Instalación (Una sola vez)

```powershell
# 1. Instalar Python 3.8+ desde python.org

# 2. Instalar dependencias
cd huawei_proxy
pip install -r requirements.txt

# 3. Generar certificado SSL
python generate_cert.py

# 4. Instalar certificado (COMO ADMINISTRADOR)
# Clic derecho en PowerShell → Ejecutar como Administrador
powershell -ExecutionPolicy Bypass -File install_cert.ps1

# 5. Configurar Chrome
powershell -ExecutionPolicy Bypass -File setup_chrome_profile.ps1
```

### Paso 2: Uso Diario

```powershell
# 1. Iniciar el proxy
cd huawei_proxy
python start_proxy.py

# 2. En otra terminal o ventana, abrir Chrome con proxy
"C:\Program Files\Google\Chrome\Application\chrome.exe" --user-data-dir="%LOCALAPPDATA%\Google\Chrome\User Data" --profile-directory="Huawei-Proxy" http://192.168.100.1

# 3. Navegar a tu router
# http://192.168.100.1
# Las funciones ocultas estarán desbloqueadas automáticamente
```

## ¿Qué hace este proxy?

### Funciones Desbloqueadas Automáticamente:

1. **Acceso Administrador Total**
   - Eleva tu cuenta a nivel 2 (telecomadmin)
   - Sin necesidad de conocer la contraseña de admin

2. **Telnet/SSH**
   - Habilita switches de Telnet y SSH
   - Acceso por línea de comandos al router

3. **Menús Ocultos**
   - Muestra opciones X_HW_DEBUG
   - Desbloquea configuración avanzada
   - Opciones de diagnóstico

4. **Captura de Tráfico**
   - Todo guardado en `captured_traffic/`
   - Analiza peticiones y respuestas
   - Encuentra más endpoints ocultos

## Ejemplo de Uso

### Habilitar Telnet en el Router

1. Inicia el proxy:
```bash
python start_proxy.py
```

2. Abre Chrome con el perfil configurado y navega a http://192.168.100.1

3. Login con tu usuario normal (el proxy lo elevará a admin)

4. Busca en los menús opciones como:
   - "Debug" o "Diagnóstico"
   - "Remote Management" o "Gestión Remota"
   - "Telnet/SSH Settings"

5. El proxy habrá modificado los valores para que:
   - TelnetSwitch = 1 (habilitado)
   - SshSwitch = 1 (habilitado)
   - Opciones visibles y habilitadas

6. Aplica los cambios y conecta por Telnet:
```bash
telnet 192.168.100.1
# Usuario: root o admin
# Contraseña: La de admin del router
```

## Análisis del Tráfico Capturado

Después de usar el router, revisa los archivos en `captured_traffic/`:

```bash
# Ver todas las URLs accedidas
grep "URL:" captured_traffic/request_*.txt

# Buscar configuración de Telnet/SSH
grep -r "Telnet\|Ssh" captured_traffic/

# Ver respuestas JSON con datos del router
grep -l "application/json" captured_traffic/response_*.txt
```

## Configuraciones Específicas de Megacable

Para Megacable México, el proxy ayuda a:

1. **Ver configuración WAN/VLAN**
   - VLAN IDs
   - Parámetros PPPoE
   - TR-069 ACS settings

2. **Acceso a estadísticas avanzadas**
   - Potencia óptica (Rx/Tx)
   - Estado de sincronización GPON
   - Información del ONT

3. **Modificar configuración bloqueada**
   - Cambiar DNS
   - Configurar port forwarding
   - Modificar WiFi avanzado

## Seguridad y Precauciones

⚠️ **IMPORTANTE**:
- Solo usa en TU router
- No modifiques configuración crítica sin saber qué hace
- Guarda backup de configuración antes de cambios importantes
- Puedes resetear el router físicamente si algo sale mal (botón reset 10 seg)

## Desinstalación

Para remover el certificado después de usar:

1. Presiona `Win + R`
2. Escribe: `certmgr.msc`
3. Navega a: Trusted Root Certification Authorities → Certificates
4. Busca: "Huawei ONT Interceptor Root CA"
5. Clic derecho → Delete

## Soporte

Tráfico capturado y logs en `captured_traffic/` te ayudarán a entender:
- Qué peticiones hace la interfaz web
- Qué respuestas da el router
- Qué parámetros se pueden modificar
- Endpoints API disponibles

## Atajos Útiles

```bash
# Proxy en modo silencioso (menos logs)
python start_proxy.py -q

# Proxy en puerto diferente
python start_proxy.py -p 9090

# Ver logs del proxy en tiempo real
python start_proxy.py | tee proxy.log
```

## Próximos Pasos

Después de familiarizarte con el proxy:

1. Analiza los binarios en `/bin` y `/lib` del firmware
2. Lee la configuración en `/configs/hw_ctree.xml` (encriptada)
3. Estudia los scripts ASP en `/web` para entender la API
4. Usa herramientas como radare2 o Ghidra para análisis de binarios
5. Documenta tus hallazgos para la comunidad
