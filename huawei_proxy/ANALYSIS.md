# Análisis de Funciones Ocultas - HG8145V5-V500R020C10SPC212

## Resumen Ejecutivo

Este documento detalla las funciones ocultas y privilegios encontrados en el firmware Huawei HG8145V5 V500R020C10SPC212 mediante análisis de la interfaz web y configuración del sistema.

## 1. Sistema de Niveles de Usuario

### Niveles Identificados

```javascript
// De web/frame_huawei/login.asp
var Userlevel = 0;  // Variable principal de nivel

// Niveles:
// 0 = Usuario básico (acceso limitado)
// 1 = Usuario normal (más funciones)
// 2 = Administrador/telecomadmin (acceso completo)
```

### Verificación de Nivel

```javascript
// web/frame_huawei/login.asp:88
var UserLeveladmin = '<%HW_WEB_CheckUserInfo();%>';

if((UserLeveladmin == '0')) {
    // Bloquear acceso a páginas de admin
    alert("El administrador no puede abrir esta página.");
}

// web/frame_huawei/login.asp:154
if (Userlevel == 2) {
    url = 'MdfPwdAdminNoLg.cgi';  // CGI de admin
    webUserDomin = 'InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.2';
}
```

## 2. Funciones X_HW_DEBUG

El namespace `X_HW_DEBUG` contiene funciones de depuración y diagnóstico normalmente ocultas.

### X_HW_DEBUG.TelnetSwitch / SshSwitch

**Ubicación**: `InternetGatewayDevice.X_HW_DEBUG.TelnetSwitch`

**Valores**:
- `0` = Deshabilitado (default para usuarios ISP)
- `1` = Habilitado (acceso remoto por Telnet/SSH)

**Archivos relacionados**:
```
web/FrameAISAP/index.asp
web/FrameAISAP/CustomApp/mainpage.asp
```

### X_HW_DEBUG.AMP.OntOnlineStatus

**Ubicación**: `InternetGatewayDevice.X_HW_DEBUG.AMP.OntOnlineStatus.ontonlinestatus`

**Función**: Estado avanzado de conexión del ONT con el OLT (Optical Line Terminal)

**Archivos**:
```
web/FrameAISAP/asp/ontOnlineStatus.asp:
<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.OntOnlineStatus.ontonlinestatus);%>

web/frame_pccw/asp/ontOnlineStatus.asp:
<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.OntOnlineStatus.ontonlinestatus);%>
```

### X_HW_DEBUG.SMP.DM.ResetBoard

**Ubicación**: `InternetGatewayDevice.X_HW_DEBUG.SMP.DM.ResetBoard`

**Función**: Reset avanzado de la placa/dispositivo

**Uso**:
```javascript
// web/FrameAISAP/index.asp:176
Form.setAction('set.cgi?x=InternetGatewayDevice.DeviceInfo&y=InternetGatewayDevice.X_HW_DEBUG.SMP.DM.ResetBoard' + '&RequestFile=html/index.html');

// web/FrameAISAP/CustomApp/mainpage.asp:413
Form.setAction('set.cgi?x=' + 'InternetGatewayDevice.X_HW_DEBUG.SMP.DM.ResetBoard'
    + '&RequestFile=html/index.html');
```

### X_HW_DEBUG.AMP.LANPort

**Ubicación**: `InternetGatewayDevice.X_HW_DEBUG.AMP.LANPort.{i}.CommonConfig`

**Función**: Información detallada de puertos LAN (estado de enlace, configuración)

**Uso**:
```javascript
// web/FrameAISAP/CustomApp/mainpage.asp:40
var EthLinkStatus = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_DEBUG.AMP.LANPort.{i}.CommonConfig, Link, GetEthLinkStatus);%>;

// web/FrameAISAP/portal/PortalInternetStatus.asp:132
var LANPortInfoList = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_DEBUG.AMP.LANPort.{i}.CommonConfig, Link, stUpLink);%>;
```

### X_HW_DEBUG.AMP.AccessModeDisp

**Ubicación**: `InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.AccessMode`

**Función**: Información del modo de acceso PON (GPON/EPON/XG-PON)

**Uso**:
```javascript
// web/frame_IraqO3/genaral.asp:40
var ontPonMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.AccessMode);%>';
var ontXGMode = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.AccessModeDisp.XG_AccessMode);%>';
```

### X_HW_DEBUG.AMP.Optic

**Ubicación**: `InternetGatewayDevice.X_HW_DEBUG.AMP.Optic`

**Función**: Información óptica detallada (potencia Tx/Rx, voltaje, temperatura, corriente de bias)

**Parámetros**:
- `TxPower`: Potencia de transmisión
- `RxPower`: Potencia de recepción
- `Voltage`: Voltaje
- `Temperature`: Temperatura del transceptor
- `Bias`: Corriente de bias del láser
- `RfRxPower`: Potencia RF de recepción
- `RfOutputPower`: Potencia RF de salida

**Uso**:
```javascript
// web/frame_IraqO3/genaral.asp:43
var opticInfos = <%HW_WEB_GetParaArryByDomain(InternetGatewayDevice.X_HW_DEBUG.AMP.Optic, TxPower|RxPower|Voltage|Temperature|Bias|RfRxPower|RfOutputPower, stOpticInfo);%>;
```

### X_HW_DEBUG.SMP.APM.ChipStatus.Optical

**Ubicación**: `InternetGatewayDevice.X_HW_DEBUG.SMP.APM.ChipStatus.Optical`

**Función**: Estado del chip óptico

**Uso**:
```javascript
// web/frame_IraqO3/genaral.asp:38
var opticPower = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.SMP.APM.ChipStatus.Optical);%>';
```

### X_HW_DEBUG.AMP.GetOptTxMode

**Ubicación**: `InternetGatewayDevice.X_HW_DEBUG.AMP.GetOptTxMode.TxMode`

**Función**: Modo de transmisión óptica

**Uso**:
```javascript
// web/frame_IraqO3/genaral.asp:39
var status = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.GetOptTxMode.TxMode);%>';
```

### X_HW_DEBUG.AMP.GetOptStaus

**Ubicación**: `InternetGatewayDevice.X_HW_DEBUG.AMP.GetOptStaus.status`

**Función**: Estado del módulo óptico

**Uso**:
```javascript
// web/frame_IraqO3/genaral.asp:42
var opticStatus = '<%HW_WEB_GetParaByDomainName(InternetGatewayDevice.X_HW_DEBUG.AMP.GetOptStaus.status);%>';
```

### X_HW_DEBUG.AMP.SetWifiCoverEnable

**Ubicación**: `InternetGatewayDevice.X_HW_DEBUG.AMP.SetWifiCoverEnable`

**Función**: Habilitar/deshabilitar cobertura WiFi extendida

**Uso**:
```javascript
// web/FrameAISAP/CustomApp/mainpage_new.asp:297
Form.setAction('set.cgi?y=InternetGatewayDevice.X_HW_DEBUG.AMP.SetWifiCoverEnable' +
    '&WifiCoverEnable=' + wifien + '&RequestFile=html/index.html');
```

## 3. CGI Endpoints Privilegiados

### Login y Autenticación

```
login.cgi               - Login principal
UserLogin              - Endpoint alternativo de login
MdfPwdNormalNoLg.cgi   - Cambio de password usuario normal (UserLevel 1)
MdfPwdAdminNoLg.cgi    - Cambio de password admin (UserLevel 2)
```

### API de Configuración

```
set.cgi                - Establecer parámetros de configuración
get.cgi                - Obtener parámetros de configuración
SendGetInfo.cgi        - Obtener información del sistema
GetRandCount.asp       - Contador aleatorio (anti-CSRF)
```

## 4. Estructura de URLs por Tipo de Usuario

### Rutas de Admin

```javascript
// web/frame_huawei/frame.asp
pwdurl = "html/ssmp/accoutcfg/accountadmin.asp";

// web/frame_huawei/Cusjs/frame.js
pwdurl = "html/ssmp/accoutcfg/accountadmin.asp";
```

### Rutas de Telecom

```javascript
// web/frame_huawei/frame.asp
pwdurl = "html/ssmp/accoutcfg/accountBeltelecom.asp";

// web/frame_huawei/Cusjs/frame.js
pwdurl = "html/ssmp/accoutcfg/accountBeltelecom.asp";
```

## 5. Menús Ocultos por ISP

Los archivos en `web/menu/` contienen configuraciones XML que controlan la visibilidad de menús según el ISP.

### Menús Relevantes Identificados

```
MenuHuawei.xml          - Menú base de Huawei
MenuAbroad.xml          - Configuración internacional
MenuArgentina.xml       - Configuración para Argentina
MenuTot.xml             - TOT (Thailand)
MenuRussian.xml         - Rusia
MenuCmccRmsReg.xml      - China Mobile
```

### Atributos de Visibilidad

Los archivos XML contienen atributos como:
- `display="none"` / `display="block"`
- `hide="true"` / `show="true"`
- User level requirements

## 6. Dominios de Configuración TR-069

### Usuario Web Normal

```
InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.1
```

### Usuario Web Admin

```
InternetGatewayDevice.UserInterface.X_HW_WebUserInfo.2
```

## 7. Features Flags

El firmware usa flags de funcionalidades que pueden estar habilitados/deshabilitados:

```javascript
// web/frame_huawei/login.asp
var SonetFlag = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_SONET);%>';
var IsPTVDF = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_PTVDF);%>';
var IsTURKSATEBG = '<%HW_WEB_GetFeatureSupport(HW_SSMP_FEATURE_MNGT_TURKSATEBG);%>';
var RegPageFlag = "<%HW_WEB_GetFeatureSupport(FT_WEB_OVERSEA_REGIST_PAGE);%>";
```

## 8. Modificaciones del Proxy

El proxy `huawei_proxy/proxy.py` intercepta y modifica:

### En Requests (Peticiones)
1. Eleva UserLevel de 0 o 1 a 2 en JSON
2. Añade headers de admin override
3. Modifica parámetros de configuración

### En Responses HTML/JavaScript
1. `var Userlevel = 0;` → `var Userlevel = 2;`
2. `display:none` → `display:block` para elementos debug/telnet/ssh
3. `disabled="disabled"` → `` (remueve disabled)
4. `"TelnetSwitch":"0"` → `"TelnetSwitch":"1"`
5. `"SshSwitch":"0"` → `"SshSwitch":"1"`
6. Clases CSS `hidden` → `visible`

### En Responses JSON
1. `"UserLevel":"0"` → `"UserLevel":"2"`
2. Habilita todos los switches de X_HW_DEBUG
3. Modifica flags de funcionalidades

## 9. Configuraciones Específicas de Megacable

Para el ISP Megacable (México), las siguientes funciones están típicamente bloqueadas:

### Bloqueadas Normalmente
- Configuración de VLAN manual
- Cambio de servidor TR-069 (ACS)
- Acceso Telnet/SSH
- Configuración avanzada de WAN
- Port forwarding avanzado
- DMZ
- Configuración de DNS manual
- Modo bridge

### Desbloqueadas por el Proxy
Todas las anteriores se vuelven accesibles con UserLevel 2.

## 10. Binarios Relevantes

Del análisis del firmware en `/bin` y `/lib`:

### /bin/aescrypt2
- Encriptación/desencriptación de configuración
- Formato AEST (mbedTLS)
- AES-256-CBC

### /bin/cfgtool
- Gestión de configuración
- API: `HW_CFGTOOL_Get/Set/Add/Del/CloneXMLValByPath`

### /lib/libhw_ssp_basic.so
- Funciones core de seguridad
- `HW_XML_CFGFileSecurity`
- `HW_XML_GetEncryptedKey`

### /lib/libhw_ssp_ssl.so
- SSL/TLS + KMC key derivation
- `CAC_Pbkdf2Api`
- Derivación de claves

## 11. Archivos de Configuración

### /configs/hw_ctree.xml
- Árbol de configuración principal
- Encriptado con AES-256-CBC
- Contiene todos los parámetros del sistema

### /configs/hw_aes_tree.xml
- Esquema de campos encriptados
- Lista de XPaths que están encriptados individualmente

### /configs/passwd
- Cuentas de usuario del sistema
- Hashes MD5-crypt (`$1$`) y SHA-512 (`$6$`)

## 12. XPaths Importantes

```
/configuration/InternetGatewayDevice/X_HW_DEBUG/TelnetSwitch
/configuration/InternetGatewayDevice/X_HW_DEBUG/SshSwitch
/configuration/InternetGatewayDevice/ManagementServer/URL
/configuration/InternetGatewayDevice/ManagementServer/Username
/configuration/InternetGatewayDevice/WANDevice/.../PPPPassword
/configuration/InternetGatewayDevice/X_HW_TOKEN
```

## 13. Vectores de Ataque Mitigados

El proxy NO implementa:
- Explotación de vulnerabilidades
- Bypass de autenticación sin credenciales
- Modificación directa de firmware
- Acceso sin password
- Backdoors

El proxy SOLO:
- Modifica respuestas HTTP/HTTPS en tránsito
- Eleva privilegios de usuarios legítimos
- Desbloquea UI ocultas
- Captura tráfico para análisis

## 14. Conclusiones

### Funciones Más Importantes Desbloqueadas

1. **Telnet/SSH**: Acceso de línea de comandos completo
2. **X_HW_DEBUG.AMP.Optic**: Diagnóstico óptico detallado
3. **X_HW_DEBUG.SMP.DM.ResetBoard**: Control de reset avanzado
4. **UserLevel 2**: Acceso completo a todas las funcionalidades

### Uso Legítimo del Proxy

- Análisis de seguridad del propio equipo
- Debugging de problemas de conexión
- Acceso a información de diagnóstico
- Configuración avanzada de red doméstica
- Investigación educativa

### Limitaciones

- Requiere credenciales válidas de usuario
- No bypassa autenticación del router
- No modifica firmware persistentemente
- Solo funciona durante la sesión del proxy

## Referencias

- Firmware: HG8145V5-V500R020C10SPC212
- Repositorio: Uaemextop/firmware-HG8145V5-V500R020C10SPC212
- Proxy: huawei_proxy/proxy.py
- Interfaz web: web/frame_huawei/
