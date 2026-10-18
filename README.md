# Metakampo Access · Escritorio Windows Server

La versión 1.7.0 administra usuarios locales Windows o Active Directory según el modo elegido. La versión actual se instala como **Metakampo-Access-Setup-x64.exe** y se abre desde una ventana propia. No necesita Python ni IIS. Consulta [DESKTOP.md](DESKTOP.md) para instalar, configurar AD y utilizar las métricas locales y los clientes RDP protegidos con DPAPI. El portal anterior se conserva en la rama `main`; esta versión está en `codex/metakampo-desktop`.

Las secciones siguientes documentan el portal original y su ejecución de desarrollo; la aplicación de escritorio utiliza el asistente y no un portal HTTPS.

Primera versión funcional de un gestor propio de identidades y contraseñas, con el sistema de diseño Freshkampo v2.1 y tema **Fresa**, seleccionado por el usuario. Aplicación para instalar dentro de la organización; backend Python/Flask/Waitress, interfaz web sin frameworks y adaptador PowerShell para AD local.

## Dashboard de uso

Incluye un dashboard de accesos Windows con métricas, filtros, gráfica diaria, eventos y cobertura. [DASHBOARD.md](DASHBOARD.md) describe cómo registrar cada servidor y desplegar el recolector PowerShell por HTTPS. En demo las métricas son ficticias; no se han integrado servidores reales desde esta Mac.

## Clientes RDP firmados

Ahora incluye **Clientes RDP**: perfil firmado, lanzador Authenticode y activación de contraseña de un solo uso. Usa el certificado empresarial existente, configurado en Windows. Los ZIP no contienen contraseñas. Consulta [RDP.md](RDP.md) para configurar certificados, HTTPS y el flujo de entrega. La firma y la conexión real no se han validado en Windows desde esta Mac.

## Funciones disponibles

- Directorio: consulta, búsqueda, filtros, alta de usuarios, habilitar/deshabilitar cuentas, desbloqueo de cuentas bloqueadas y restablecimiento de contraseña.
- Generación criptográfica de contraseñas de **15 caracteres por defecto**, ampliable hasta 64, con mayúsculas, minúsculas, números y símbolos.
- Registro persistente de huellas HMAC y restricción única en SQLite: no vuelve a emitir una contraseña registrada por esta instancia mientras se conserve la base y la clave maestra. No conoce las contraseñas actuales de AD ni asegura unicidad entre otras aplicaciones.
- Bóveda: genera y guarda credenciales cifradas con AES-256-GCM; consulta con reautenticación. La clave generada para una credencial de bóveda debe aplicarse al sistema correspondiente por separado. No importa automáticamente contraseñas existentes ni rota servicios.
- Auditoría de operaciones, consultas a la bóveda y accesos. No registra contraseñas, clave maestra ni contenido secreto.
- Autenticación administrativa, sesión de 15 minutos con revocación, CSRF, limitación de intentos, CSP, cookies HttpOnly/SameSite y no-store.
- Inter local, Heroicons v2, tokens oficiales, responsive, foco visible, diálogos con captura de foco, modo claro/oscuro y reducción de movimiento. No requiere CDN ni fuentes externas.

## Probar en esta Mac

Ejecuta `start.command` desde Terminal o abre el archivo en Finder. En el primer arranque solicitará que elijas una contraseña de administrador de al menos 15 caracteres. No hay contraseña predeterminada.

```bash
cd /Users/robertomora/Documents/ChatGPT/SERVIDORES/freshkampo-access
./start.command
```

Después abre http://127.0.0.1:8765 e inicia sesión con el usuario `admin` y la contraseña que elegiste. Los seis usuarios iniciales son ficticios. El modo demo modifica solo SQLite; no cambia cuentas de Windows ni conecta al dominio. `Ctrl+C` detiene el servidor.

## Preparar Windows Server y AD real

**El adaptador está implementado; no se ha probado contra un dominio real desde esta Mac.** Valida primero en una OU de pruebas y revisa los registros del controlador de dominio. No desplegar directamente a toda la organización.

1. Copia el proyecto a un servidor miembro del dominio; excluye `.venv`, `data` y archivos de prueba temporales. Instala Python 3.11+ y las herramientas RSAT con el módulo `ActiveDirectory` para Windows PowerShell 5.1.
2. Ejecuta la aplicación con una cuenta de servicio que tenga permisos delegados únicamente en la OU autorizada: leer, crear usuarios, habilitar/deshabilitar, desbloquear, restablecer contraseñas y modificar `pwdLastSet`. No necesita ser Domain Admin. El script usa la identidad Windows del proceso; no guarda credenciales de dominio.
3. Configura las variables del proceso antes de arrancar:

| Variable | Configuración |
|---|---|
| `FK_MODE` | `ad` |
| `FK_AD_SERVER` | FQDN del controlador de dominio |
| `FK_AD_OU` | DN de la OU autorizada, incluidos sus descendientes |
| `FK_AD_UPN_SUFFIX` | Sufijo UPN válido del dominio |
| `FK_MASTER_KEY` | 32 bytes aleatorios codificados en base64; aprovisionar mediante el gestor de secretos del servidor |
| `FK_TRUSTED_HOSTS` | Nombre DNS del portal, sin esquema ni puerto; separa varios con comas |
| `FK_DATA_DIR` | Directorio dedicado con ACL restringida a la cuenta de servicio y administradores de respaldo |

Genera una clave una sola vez, sin imprimirla, y entrégala al servicio a través del mecanismo de secretos elegido. Ejemplo para una sesión de preparación PowerShell:

```powershell
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$env:FK_MASTER_KEY = [Convert]::ToBase64String($bytes)
$rng.Dispose()
[Array]::Clear($bytes, 0, $bytes.Length)
```

Este ejemplo solo establece la variable en la sesión actual; no la conserva tras reiniciar. Conserva la clave en el gestor de secretos y aprovisiónala al proceso en cada arranque. **No reemplaces la clave al reiniciar**: perderías acceso a la bóveda y continuidad de las huellas. No coloques claves en scripts, Git o notas.

4. Inicia desde el proyecto con `windows\Start-Access.ps1 -Mode ad`. Solicitará el alta del administrador local si no existe. La cuenta `admin` de la interfaz es distinta de la cuenta de servicio de Windows.
5. Publica por **HTTPS** con certificado válido mediante un proxy inverso interno (por ejemplo IIS/ARR) a `127.0.0.1:8765`. Waitress escucha solo en loopback. En modo AD las cookies son `Secure`: el acceso administrativo requiere el portal HTTPS. No se ha configurado IIS ni un servicio Windows en este equipo.
6. Verifica conectividad del servidor al controlador de dominio y permisos RSAT. Las altas y restablecimientos fuerzan cambio de contraseña en el siguiente inicio de sesión. AD aplica también su propia política y puede rechazar una clave generada; configura una longitud compatible en el gestor.
7. El script resuelve las cuentas por GUID, comprueba pertenencia a la OU y rechaza cuentas con `adminCount=1` para operaciones de cuenta. No elimina usuarios ni administra grupos privilegiados. La política de generación del gestor **no modifica las GPO ni las políticas de contraseña de AD**.

## Datos, respaldo y límites de esta versión

- `data/access.sqlite3` contiene usuarios ficticios en demo, credenciales cifradas, auditoría, huellas, activaciones RDP cifradas temporales y hash PBKDF2-SHA256 del administrador (1 millón de iteraciones).
- En demo `data/demo.key` contiene la clave de cifrado y debe protegerse junto con el equipo. El cifrado no protege frente a una persona que ya pueda leer la base y esa clave. En AD la clave se exige desde el entorno y no se escribe en un archivo del proyecto.
- Respaldar SQLite con su API de backup o detener el proceso durante la copia. Respaldar la clave por separado mediante el gestor de secretos. Probar restauración. Restricción de ACL en Windows se configura en el servidor, no automáticamente.
- Las contraseñas de AD se muestran una vez y se ocultan a los 60 segundos o cuando la pestaña pierde visibilidad. No se guardan automáticamente en la bóveda. El portapapeles puede conservar una copia hasta que se sobrescriba.
- Primera versión con **un administrador local**. No incluye SSO/MFA, roles multiadministrador, aprobaciones, asignación de grupos, edición general de atributos, importación masiva, notificaciones ni registro externo inmutable. Para operación empresarial multiusuario hay que completar estos controles.
- La auditoría reside en SQLite y no es inmutable ante un administrador del servidor.
- Las operaciones AD constan de varios pasos; un timeout o error puede ocurrir después de un cambio parcial. Antes de reintentar, comprueba el estado real en AD. No hay rollback distribuido ni conciliación automática.
- No se ha instalado ni publicado en ningún servidor del usuario, ni se han cambiado cuentas reales.

## Verificación

```bash
.venv/bin/python -m unittest discover -s tests -v
```

En Windows: `.venv\Scripts\python.exe -m unittest discover -s tests -v`.

La suite verifica autenticación, CSRF, bloqueo de intentos, cifrado autenticado y manipulación, ausencia de secretos en listado/auditoría/base, calidad y colisiones de generación, persistencia de política, operaciones demo, cabeceras y contrato del adaptador con mocks. Además verifica entregas RDP, HTTPS, revocación, caducidad y activación única concurrente. La firma nativa se simula en las pruebas de servicio. Esto no sustituye pruebas de integración con AD, certificados y MSTSC en Windows.

## Referencias

- Diseño: guía Freshkampo v2.1 y módulo `DS_Tema_Fresa.md` instalados en el skill Freshkampo; tokens copiados en `static/tokens.css`.
- [New-ADUser](https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-aduser)
- [Set-ADAccountPassword](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adaccountpassword)
- [Seguridad de Flask](https://flask.palletsprojects.com/en/stable/web-security/)
- [AES-GCM de cryptography](https://cryptography.io/en/latest/hazmat/primitives/aead/)
- Fuentes e íconos con sus licencias en `static/fonts/LICENSE-Inter.txt` y `static/LICENSE-Heroicons.txt`.

## Protección de IP y Telegram (1.6.0)

Nuevo módulo **Protección de IP** para el servidor instalado. Empieza desactivado. Configura primero la lista blanca y después el umbral (1–1000 intentos), periodo (1–1440 minutos) y duración del bloqueo (1–43200 minutos). Valores iniciales: 5 fallos en 10 minutos y bloqueo de 60 minutos. Guardar política reinicia la ventana de conteo; no aplica bloqueos por eventos históricos.

- Cuenta eventos Security 4625 tipo 10 del servidor local. Puede incluir tipo 3 de forma explícita: incluye NLA y otros servicios de red y no representa exclusivamente RDP. Nunca usa eventos demo o de recolectores remotos para bloquear este servidor. Requiere auditoría Windows de fallos de inicio de sesión y acceso a Security. El recolector consulta aproximadamente cada 60 segundos y el motor revisa cada 10 segundos; no es un filtro instantáneo.
- Crea reglas propias persistentes de entrada, para **todos los protocolos desde una IP exacta**, en todos los perfiles. Puede interrumpir sesiones/servicios de una IP compartida por NAT o VPN. No toca reglas ajenas. Hasta 1000 bloqueos activos; al llegar al límite muestra error y requiere revisión. La verificación confirma presencia/configuración de regla y políticas locales; no sustituye una prueba de tráfico real.
- Lista blanca IPv4/IPv6 o redes CIDR: prioridad sobre bloqueo automático y manual, incluye IPv4 mapeada. Agregar una excepción guarda primero la exclusión y retira bloqueos propios coincidentes. Si Windows rechaza retirar, muestra pendiente/error y reintenta; no afirma éxito. No cambia bloqueos de otras aplicaciones, GPO, routers o monitores anteriores. Loopback, multicast, no especificadas y enlace local se excluyen siempre.
- Puedes bloquear manualmente, desbloquear o convertir una IP bloqueada en excepción. Retirar un bloqueo reinicia su contador; fallos nuevos pueden volver a bloquearla. Desactivar protección retira reglas automáticas; los manuales conservan su vencimiento. Retirar una excepción solo permite contar fallos nuevos. Historial con actor y estado; últimos 200 bloqueos, 100 acciones y 50 alertas visibles.
- La configuración/whitelist/reglas son comunes a Local/AD del mismo perfil propietario, en `ip-protection.sqlite3`, con la ACL privada existente. Demo usa otra base y simula reglas/envíos.

### Reutilizar el bot existente

El instalador incorpora el adaptador `windows/Protect-IP.ps1`, **sin token**. Reutiliza el monitor instalado en `%ProgramData%\FreshkampoTelegramMonitor`: `config.json` con `ChatId` numérico y `token.dpapi` DPAPI LocalMachine, según el monitor preparado anteriormente. El propietario elevado necesita leerlos con sus ACL actuales. No copia el token, no debilita permisos, no modifica sus tareas/configuración y no ejecuta sus scripts como código. Lee la configuración/credencial y usa sendMessage contra la API HTTPS fija de Telegram. Si el monitor usa `TemaId`, lo conserva. Para otras rutas/formato se requiere adaptar la integración; no explora archivos arbitrarios.

**Comprobar monitor** verifica configuración y acceso a DPAPI; no envía prueba ni confirma entrega. Activa avisos en el segundo paso de Configurar protección. Genera alerta al confirmar una regla propia; contiene IP, servidor, fallos, fecha/vencimiento UTC y referencia, sin contraseñas. Las alertas pendientes persisten y reintentan con espera exponencial (30 s a 1 h). Telegram no bloquea el registro del bloqueo. Una confirmación perdida o cierre justo después de enviar puede producir duplicados (entrega al menos una vez); la referencia los identifica. No usa getUpdates ni compite con /restart. Si los servidores ya tienen el mismo bot/grupo, comparten ese destino; no cambia bots existentes ni necesita servicio central.

### Disponibilidad y actualización

El proceso propietario debe estar abierto para detectar fallos, reintentar Telegram y retirar reglas al vencer. **Las reglas persisten si la aplicación se cierra, incluso después del vencimiento previsto; se revisan al reabrir.** No añade servicio/tarea ni modifica el monitor de reinicios. Antes de desinstalar, desactiva la política y retira bloqueos manuales. Windows debe permitir reglas locales (GPO), perfiles activos y propietario elevado; cliente compartido conserva asInvoker. No cambia ExecutionPolicy. Cambios requieren contraseña propia y CSRF; auditoría individual.

Instala con el propietario original. Añade primero las IP de administración/VPN a la lista blanca, comprueba el monitor sin enviar, habilita política/alertas y realiza un piloto desde una IP de prueba fuera de la lista blanca, conservando acceso de recuperación. No se enviaron mensajes reales ni se modificó el firewall del servidor del usuario durante el desarrollo.

Referencias: [New-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule), [Telegram sendMessage](https://core.telegram.org/bots/api#sendmessage).

## Menú y vencimientos (1.7.0)

Menú lateral colapsable y vencimiento de cuentas Windows/AD con deshabilitación confirmada y alerta Telegram. Consulta la sección 1.7.0 de [DESKTOP.md](DESKTOP.md) para fechas, zona horaria, disponibilidad, reintentos y restricciones.

La aplicación de escritorio 1.8.0 incorpora **Actualizaciones** desde GitHub Releases, con metadatos firmados, verificación del instalador, respaldo cifrado y confirmación del propietario. Se necesita una instalación manual inicial de 1.8.0; las siguientes se descargan y aplican desde el programa. Consulta [DESKTOP.md](DESKTOP.md) y [RELEASE-NOTES.md](RELEASE-NOTES.md).

La versión1.9.0 ejecuta la **protección IP** mediante una tarea SYSTEM al inicio, independiente de cerrar Metakampo o cerrar sesión. Muestra su actividad, consulta fallos recientes directamente y da un resultado visible al comprobar el monitor. Los otros módulos conservan sus requisitos de propietario abierto. Consulta [RELEASE-NOTES.md](RELEASE-NOTES.md) y la sección1.9.0 de [DESKTOP.md](DESKTOP.md).
