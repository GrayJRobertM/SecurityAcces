# Clientes RDP firmados

El usuario confirmó que usará un certificado empresarial existente. Esta extensión genera perfiles `.rdp` y un lanzador PowerShell firmado. No genera un ejecutable `.exe` ni instala software en los equipos.

## Uso

1. Entra en **Clientes RDP → Generar cliente RDP**, o usa el botón de computadora junto a un usuario del directorio.
2. Indica el servidor, puerto y usuario con formato `DOMINIO\usuario` o `usuario@dominio`.
3. En modo AD, introduce la contraseña **vigente** de esa cuenta y confirma tu contraseña administrativa. El gestor genera un código fuerte de activación automáticamente.
4. Descarga el ZIP y copia el código que se muestra temporalmente. Entrega el código al destinatario por un canal separado del ZIP.
5. El destinatario extrae los archivos en Windows y ejecuta `Conectar.ps1` desde Windows PowerShell 5.1 o PowerShell 7. La firma y cadena de confianza deben ser válidas conforme a las políticas corporativas. No hay que ejecutar como administrador.
6. La primera ejecución pide el código de activación. El lanzador accede al portal HTTPS, recibe la contraseña una sola vez y la guarda como credencial `TERMSRV/<servidor>` en el Administrador de credenciales de Windows del **usuario actual, en ese equipo**. Después abre `Conexion.rdp` con `mstsc.exe`.
7. Los siguientes accesos desde ese mismo perfil de Windows usan la credencial guardada. Copiar el ZIP a otro equipo no copia la credencial ni permite reutilizar la activación.

No se cambia ni se extrae la contraseña de Active Directory durante la generación. La contraseña introducida debe estar vigente; el gestor no la valida autenticándose contra el dominio. La cuenta debe tener permisos RDP y el servidor debe aceptarla. Si la cuenta tiene cambio obligatorio de contraseña o contraseña caducada, cambia la clave mediante el flujo autorizado antes de usar RDP con NLA.

## Configurar la firma en Windows Server

Configura estas variables **en el proceso de la aplicación**, además de las variables AD y clave maestra del README:

| Variable | Valor |
|---|---|
| `FK_RDP_CERT_HASH` | Huella del certificado utilizado para publicar archivos RDP, sin espacios. La herramienta nativa usa `/sha256`; acepta aquí identificadores hex de 40 o 64 caracteres según el certificado/herramienta de Windows. |
| `FK_RDP_CERT_STORE` | `CurrentUser` por defecto; también `LocalMachine`. El certificado debe estar en `My`, tener clave privada y ser válido. |
| `FK_RDP_SCRIPT_CERT_HASH` | Huella del certificado de **firma de código** para `Conectar.ps1`. Si se omite se usa el certificado RDP, pero este debe admitir Code Signing (OID 1.3.6.1.5.5.7.3.3). Un certificado solo para TLS no basta para firmar el lanzador. |
| `FK_RDP_PORTAL_URL` | Origen HTTPS interno al que acceden los destinatarios; por ejemplo `https://access.empresa.local`, sin rutas, parámetros ni credenciales. Debe tener un certificado HTTPS válido. |
| `FK_RDP_TIMESTAMP_URL` | Opcional: servicio corporativo de sellado de tiempo HTTPS para Authenticode. Si se omite, el lanzador no recibe timestamp; su vigencia queda sujeta a las políticas de Windows y al certificado. |

Los certificados se seleccionan de los almacenes existentes. El programa **no crea certificados autofirmados, no importa raíces ni publica claves privadas**, y no cambia la política de ejecución. La cuenta que ejecuta el servicio debe tener acceso a la clave privada. La confianza en el emisor y el editor se administra por la PKI/GPO empresarial.

Los scripts del servidor (`directory.ps1` y `sign-rdp.ps1`) también deben estar autorizados o firmados conforme a la política de ejecución empresarial; no se incluye un bypass.

Requiere `rdpsign.exe` de Windows Server 2016+ y Windows PowerShell. La aplicación comprueba que `rdpsign` emita `signature:s:` y `signscope:s:`. Firma el lanzador con `Set-AuthenticodeSignature` y exige resultado `Valid`. Si alguna firma falla, no entrega un paquete de producción ni guarda una activación.

La comprobación de firma y confianza completa se hace en Windows: el lanzador comprueba su propia firma Authenticode, fija el certificado firmante por SHA-256 y valida el SHA-256 de los bytes exactos del RDP firmado. MSTSC comprueba la firma nativa y el servidor de destino conforme a las políticas del equipo.

El portal debe estar publicado por HTTPS con el proxy interno descrito en README. Waitress confía únicamente en `X-Forwarded-Proto` y `X-Forwarded-For` recibidos desde el proxy en `127.0.0.1`. Configura el proxy para sobrescribir esos encabezados con el protocolo e IP reales, descartando los valores enviados por el cliente; esto permite limitar los intentos por IP sin agrupar a todos los destinatarios; no expongas el listener backend de loopback. El cliente necesita acceso HTTPS al gestor solo al activar; RDP requiere su conectividad habitual al servidor/puerto.

## Protección y alcance de las credenciales

- El ZIP contiene `Conexion.rdp`, `Conectar.ps1` y `LEEME.txt`. No contiene contraseñas, código de activación, contraseña administrativa, PFX ni clave privada. El identificador de entrega y la URL del portal están en la configuración firmada del lanzador.
- La contraseña de destino se guarda temporalmente cifrada con AES-256-GCM en SQLite. El código se guarda mediante hash PBKDF2-SHA256. Caduca **30 minutos después de generar el paquete** y solo puede canjearse una vez.
- El canje exige HTTPS, no usa la sesión de administrador ni admite llamadas desde un origen web. El código va en el cuerpo JSON, nunca en la URL. Tiene límite de intentos; el consumo está serializado en SQLite para evitar dos entregas concurrentes.
- Al activarse, revocarse o detectarse caducidad, se pone a NULL el secreto de entrega activo. Esto no borra copias previas de respaldo o todas las huellas forenses de SQLite. La caducidad se exige incluso si el servicio estuvo inactivo.
- Los metadatos de entregas quedan disponibles para auditoría, sin mostrar contraseña ni código. **Revocar** detiene una activación pendiente; no borra credenciales ya guardadas ni revoca permisos de AD.
- El lanzador usa `CredWriteW`, con secreto Unicode y memoria nativa limpiada después de usarla. No pone la contraseña en argumentos `cmdkey /pass:` ni en archivos locales. Windows protege el almacén bajo el contexto del usuario. Procesos que ya actúan como ese usuario pueden acceder a credenciales genéricas; no es una protección frente a un equipo o perfil comprometido.
- Windows conserva una credencial por destino/tipo. Preparar otro paquete para el mismo servidor en el mismo perfil puede reemplazar la credencial guardada anteriormente; para usar varias cuentas, vuelve a preparar la cuenta correcta o usa perfiles Windows separados.
- No se modifica NLA, Credential Guard, la confianza TLS ni las políticas de credenciales guardadas. Si una GPO o Credential Guard impide usar la credencial guardada, el cliente puede solicitar credenciales o rechazar la conexión; el gestor no lo desactiva.
- Si la activación se consume pero falla la escritura local o se interrumpe la conexión HTTPS, emite un nuevo paquete: el canje no es reintentable. La activación no vincula criptográficamente el código a una persona o máquina previamente registrada; quien tenga ZIP y código durante su vigencia puede activarlo. Entrégalos al destinatario autorizado.
- Al cambiar la contraseña de la cuenta, la credencial local puede quedar obsoleta; genera una nueva entrega o actualízala por el flujo empresarial. No hay rotación automática en esta extensión.
- RDP directo a DNS/IPv4 y puerto TCP, sin integración de RD Gateway o RemoteApp en esta versión.

## Modo demo y pruebas

En modo demo se exporta **solo un perfil sin firma ni contraseña**, con nombre y aviso explícitos. No tiene lanzador ni registro de activación. El botón no afirma que esté firmado.

Pruebas automáticas: autenticación/CSRF/HTTPS, validación de destino contra inyección RDP, ausencia de secretos en el ZIP, cifrado de entrega, revocación, caducidad, bloqueo de intentos y canje único ante solicitudes concurrentes. La firma se simula en las pruebas de servicio; no se presenta esa simulación como una firma real.

**Pendiente de validar en Windows:** firma con el certificado del usuario, ejecución del lanzador bajo las GPO reales, escritura/lectura de Credential Manager, certificados del servidor RDP y conexión MSTSC efectiva. Esta Mac no dispone de `rdpsign.exe` ni de la clave privada empresarial.

## Referencias

- [rdpsign](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rdpsign)
- [Set-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-authenticodesignature)
- [CredWriteW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credwritew)
- [CREDENTIALW y persistencia de credenciales](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw)
- [Propiedades RDP admitidas](https://learn.microsoft.com/en-us/azure/virtual-desktop/rdp-properties)
