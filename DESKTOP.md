# Metakampo Access · Aplicación Windows Server

Versión 1.3.0, x64. Instalador: **Metakampo-Access-Setup-x64.exe**. Aplicación instalada: **MetakampoAccess.exe**.

## Importar y exportar usuarios con contraseñas

En **Directorio de usuarios** usa **Exportar usuarios** o **Importar y sincronizar**. Exportar, previsualizar la importación y aplicar los cambios requieren confirmar la contraseña del administrador **de la instalación actual**. No se sincroniza la contraseña de `admin` ni se copia la clave maestra o la configuración del servidor.

Con **Incluir contraseñas**, se genera un archivo `.fksync` cifrado con AES-256-GCM y una clave de transferencia independiente. La derivación usa PBKDF2-SHA256, 600.000 iteraciones y sal aleatoria; el formato autentica el contenido. Elige una clave fuerte o usa **Generar clave de transferencia**, consérvala y entrégala por separado al operador de la otra instalación. Ambas instalaciones pueden tener contraseñas administrativas y claves maestras diferentes. El archivo se abre con su clave de transferencia y, al aplicar, sus secretos se vuelven a cifrar con la clave local protegida por DPAPI.

**AD no permite recuperar las contraseñas actuales de sus usuarios.** A partir de esta versión se guardan cifradas las contraseñas creadas/restablecidas por el gestor. Para exportarlas se compara el dominio, GUID y versión de replicación de `pwdLastSet`; la cuenta Windows debe poder leer esos metadatos. Las cuentas cuya contraseña no existe en el gestor, cambió fuera de él, fue modificada al primer inicio obligatorio, no puede verificarse o está protegida quedan fuera del archivo con contraseñas. La interfaz informa cuántas se omitieron. Si no hay ninguna disponible, la exportación se rechaza. No se inventan claves ni se restablecen cuentas para exportar. Las cuentas anteriores a 1.2.0 no tienen claves almacenadas; para incorporar una, restablécela explícitamente desde el directorio, sabiendo que reemplaza su contraseña vigente.

Las instalaciones que consultan el **mismo AD** comparten naturalmente las cuentas. Si el archivo coincide con el mismo dominio, GUID y versión de contraseña, la importación sincroniza la copia local sin volver a cambiar la clave en AD. Un archivo antiguo o un controlador cuya versión aún no coincide se rechaza; comprueba replicación y vuelve a exportar. En un dominio diferente, la vista previa indica las altas y contraseñas que se restablecerán. AD puede rechazarlas por su política o permisos; no se omiten esos controles. Las altas y restablecimientos conservan el cambio obligatorio al próximo inicio de sesión; cuando el usuario cambie su clave el gestor ya no podrá exportar aquella contraseña inicial como vigente.

El CSV UTF-8 **sin contraseñas** utiliza exactamente `username,name,department,enabled`; `enabled` acepta true/false o 1/0. Se admite coma o punto y coma. Las contraseñas en CSV no se aceptan: usa `.fksync`. Los campos exportados que podrían interpretarse como fórmulas de hoja de cálculo se escapan. Los nombres de cuenta se usan como clave de conciliación (sin distinguir mayúsculas); no se renombran, eliminan ni asignan grupos. Se actualizan nombre mostrado, departamento y habilitación/deshabilitación. Las cuentas ausentes del archivo permanecen intactas. Cada archivo admite hasta 500 cuentas y 1 MiB.

La vista previa no hace cambios y caduca en 15 minutos, está ligada a la sesión y se utiliza una vez. Se verifica de nuevo el directorio y las versiones de contraseña antes de aplicar. Revisa especialmente los cambios de estado y los restablecimientos. La importación se procesa en segundo plano dentro de la aplicación y registra su progreso en **Historial de importaciones**. Mantén la ventana abierta. Si hay un fallo o se cierra la aplicación, el lote queda parcial/interrumpido y no se reintenta automáticamente; comprueba AD antes de previsualizar otra vez. No existe transacción distribuida ni rollback global de AD. En un dominio con administradores concurrentes pueden producirse cambios externos durante el lote; la comprobación de metadatos es una detección de cambios, no una autenticación de cada contraseña.

La acción **Consultar contraseña administrada** requiere reautenticación y muestra la clave temporalmente solo si está disponible y su versión sigue vigente. No aparece en listados, auditoría, respuestas de vista previa, CSV ni resultados de importación. El archivo `.fksync` es portátil deliberadamente; su contenido y la clave de transferencia permiten conocer sus contraseñas, por lo que deben entregarse por canales seguros a las personas autorizadas.

## Instalar y abrir

1. Usa Windows Server 2019, 2022 o 2025 x64 **con experiencia de escritorio**. Server Core no dispone de la interfaz requerida. Ejecuta el instalador como administrador; instala el programa, sus dependencias Python y el runtime oficial WebView2 incluido. No requiere Python, IIS, un portal publicado ni acceso a Internet para instalar. El instalador de esta primera entrega no tiene firma Authenticode empresarial.
2. Abre **Metakampo Access** desde Inicio con la cuenta Windows que administrará la aplicación. Esa cuenta será propietaria de sus datos y debe conservarse. No hay contraseña administrativa predeterminada.
3. Elige **Demostración** para probar sin tocar AD, o **Active Directory** para operar con tu dominio. En AD necesitas RSAT Active Directory, el FQDN del controlador, el DN de la OU autorizada y el sufijo UPN. El asistente comprueba el módulo, el acceso al controlador y que la OU existe; no cambia cuentas como prueba de permisos.
4. Crea la contraseña de `admin`, con al menos 15 caracteres, mayúsculas, minúsculas, números y símbolos. Es distinta de la contraseña Windows. Inicia sesión en la aplicación con ella.
5. Para ajustar dominio/OU/certificados después, cierra el programa y abre **Configurar Metakampo Access** desde Inicio. Debes confirmar la contraseña administrativa actual. Puedes elegir Usuarios locales, Active Directory o Demostración; cada entorno conserva sus datos separados.

## Exclusivamente en este servidor

La interfaz vive dentro de una ventana de escritorio. El transporte interno escucha en `127.0.0.1`, con puerto aleatorio y una autorización efímera exclusiva de la ventana; rechaza navegadores sin esa autorización, hosts distintos, orígenes externos, recolectores por red y activaciones RDP por red. No publica un puerto accesible desde otros equipos ni configura excepciones de firewall. Cerrar la ventana detiene la aplicación y su lector de eventos.

Los datos residen en `%LOCALAPPDATA%\Freshkampo\Access` de la cuenta Windows que abre el programa. La configuración y la clave maestra se cifran con **DPAPI CurrentUser**, y se verifica el identificador de la máquina y el SID de la cuenta. La carpeta restringe su ACL a esa cuenta y SYSTEM. Copiar sus archivos a otro equipo o cuenta no habilita su uso. Los secretos de la bóveda siguen cifrados con AES-256-GCM.

Esta protección no constituye una defensa frente a un administrador que controla el sistema operativo. Otra instalación limpia es una instancia independiente. No se incluye migración de la bóveda a otro servidor; conserva respaldos del perfil Windows y prueba la recuperación en el mismo entorno con TI.

## Active Directory y contraseñas

La cuenta Windows del programa usa sus permisos de dominio; no se guardan contraseñas de dominio para conectar al controlador. Delega únicamente los permisos necesarios sobre una OU de pruebas antes de ampliar el uso: consulta/alta, restablecimiento, habilitación/deshabilitación, desbloqueo y cambio obligatorio de contraseña. No uses Domain Admin para la operación habitual.

Las contraseñas generadas tienen **15 caracteres por defecto**, con longitud configurable 15–64. El registro de huellas evita repetir contraseñas generadas por esta instancia mientras se conserve su base y clave; no puede comparar las contraseñas existentes en AD. Las GPO y políticas de AD siguen aplicándose.

## Métricas de este servidor

En modo AD el programa lee directamente el registro **Security local**, cada 60 segundos mientras está abierto; recupera hasta 90 días de eventos que aún existan en Windows. Conserva cursor y eventos en una transacción, elimina duplicados y marca pérdidas por limpieza del registro o rotación del historial. Cuando se cierra, no lee nuevos eventos; los disponibles se recuperan al reabrir.

La cuenta Windows necesita permisos para leer Security (por ejemplo, delegación al grupo Event Log Readers validada en el servidor). Habilita mediante tu política Windows la auditoría de logon/logoff y otros eventos requeridos: 4624, 4625, 4634, 4778 y 4779. Sin eventos o permisos, el dashboard muestra cobertura ausente o desactualizada. No modifica automáticamente la política de auditoría.

Se distinguen accesos RDP (tipo 10), interactivos locales (2/7/11) y fallos de red (tipo 3). Se muestran accesos, fallos, usuarios, tendencias, ranking e historial. Esto no mide duración de sesiones ni verifica MFA. Se recogen solo eventos del servidor instalado; administrar usuarios del dominio no implica observar todos los logins del dominio.

## Clientes RDP locales firmados

Configura las huellas y almacén de tus certificados existentes, con acceso a sus claves privadas. El lanzador necesita certificado con EKU de firma de código y cadena de confianza válida. No se crea confianza automática ni se omite la política de ejecución.

El ZIP contiene `Conexion.rdp`, `Conectar.ps1` firmado y las instrucciones. La contraseña vigente queda dentro del lanzador **cifrada con DPAPI**, no en texto claro ni como argumento de proceso. El lanzador verifica firma, perfil firmado, máquina y SID antes de guardar la credencial Windows y abrir MSTSC. Funciona solo desde el servidor y la cuenta Windows que lo generó. No requiere portal ni código de activación.

Elimina la credencial `TERMSRV/destino` en el Administrador de credenciales para retirar el almacenamiento local; cambiar la contraseña de AD invalida los paquetes antiguos. No se exportan credenciales utilizables en otros equipos. Se conservan NLA y validación del servidor. Las políticas de RDP/Credential Guard pueden impedir el uso de credenciales guardadas y exigir ingreso manual. **No incluye MFA**; requiere una implementación de MFA para RDP separada.

## Mapa de accesos

Abre **Mapa de accesos**. Filtra por periodo, cuenta y actividad; acerca el mapa o arrastra para separar ubicaciones próximas. Al pulsar un punto o **Ver usuarios**, consulta todas las cuentas y eventos de sus IPs, con fecha, IP, servidor y resultado. Usa **Ver más eventos** para continuar el historial del punto. Las ubicaciones se agrupan por coordenadas aproximadas; no se ocultan los usuarios que comparten una IP o VPN.

La geolocalización se calcula **sin conexión**, mediante DB-IP City Lite (octubre 2026, CC BY 4.0), incluida en el instalador, y cartografía local Natural Earth de dominio público. No se envían nombres, eventos ni IPs observadas a APIs externas ni a un proveedor de mapas. La base es una instantánea; las ubicaciones cambian con el tiempo. No se descarga una base nueva automáticamente. Para reemplazarla por una MMDB compatible, con la aplicación cerrada copia una base válida a `%LOCALAPPDATA%\Freshkampo\Access\geodata\city.mmdb` y conserva su licencia/atribución; si se emplea otro proveedor debe actualizarse la atribución del producto. Una base ausente o inválida no bloquea el historial: los orígenes aparecen sin ubicación.

Las IP privadas, locales, ausentes, inválidas o no conocidas se muestran en **Orígenes sin ubicación**. No se ubican en el servidor, en el centro del mapa ni en la sede corporativa por suposición. La IP puede ser la del proveedor, salida NAT, VPN o gateway; no prueba la ubicación física de una persona. En un fallo aparece la cuenta declarada en el intento, cuya autenticación no quedó confirmada. Los fallos de red tipo 3 se etiquetan aparte; no se atribuyen automáticamente a RDP. El mapa muestra **eventos históricos**, no conexiones activas ni MFA confirmado.

El mapa procesa hasta 2.000 orígenes distintos más recientes por filtro y muestra un aviso cuando excede esa cobertura. Reduce el periodo o filtra por usuario para revisar otros. El panel de eventos pagina en bloques de 100 sin perder cuentas compartidas. En demostración tanto las ubicaciones como los eventos son ficticios y se rotulan como tales. Las actualizaciones del instalador conservan la bóveda y la configuración de la misma cuenta Windows.

## Compilar y verificar

La rama `main` conserva el portal original. La rama `codex/windows-desktop` contiene esta versión. El workflow `.github/workflows/windows-desktop.yml` compila en Windows Server 2022, ejecuta pruebas (incluida la interoperabilidad DPAPI entre Python y Windows PowerShell), analiza sintaxis PowerShell, prueba el ejecutable congelado, compila el instalador y verifica instalación silenciosa, ejecutable instalado y apertura/cierre de la ventana nativa WebView2. El artefacto de GitHub Actions contiene el `.exe` y su SHA256. La verificación de integración en el dominio real, firma con tus certificados y conexión MSTSC debe realizarse en tu servidor.

Fuentes: [DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata), [pywebview](https://pywebview.flowrl.com/api/), [Inno Setup](https://jrsoftware.org/ishelp/), [WebView2](https://developer.microsoft.com/en-us/microsoft-edge/webview2/).

## Actualización de marca 1.2.1

Metakampo sustituye el nombre visible anterior y usa el emblema M proporcionado por el usuario. El icono transparente se adaptó desde esa imagen; el original se conserva en static/metakampo-logo-original.png. Se conservan AppId, carpeta de instalación y datos `%LOCALAPPDATA%\Freshkampo\Access`, entropía DPAPI e identificadores del formato .fksync para abrir instalaciones y exportaciones anteriores. No se migra ni restablece la bóveda. Cierra el programa y actualiza con el mismo usuario Windows y equipo.

## Modos de directorio desde 1.3.0

- **Usuarios locales · Este servidor**: usa las cuentas SAM del servidor instalado, en WORKGROUP o como miembro de dominio. No necesita controlador, OU ni RSAT AD. Abre Metakampo **como administrador**, con la misma cuenta Windows propietaria de la instalación. No funciona en un controlador de dominio. Los usuarios se identifican por SID y RDP usa EQUIPO\usuario. Crea cuentas estándar en el grupo Usuarios; no añade Administradores ni Usuarios de escritorio remoto. La política local controla requisitos/expiración de contraseña; el gestor local no impone cambio obligatorio al primer inicio. El campo Departamento corresponde a la descripción de la cuenta Windows.
- **Active Directory · Uso real**: conserva el adaptador existente y su OU autorizada, herramientas RSAT, controlador, UPN y permisos delegados. Se mantiene el cambio obligatorio al siguiente inicio al crear/restablecer.
- **Demostración**: datos ficticios; no modifica Windows ni AD.

Para cambiar de modo cierra el programa y abre **Configurar Metakampo Access** (como administrador para modo local). Confirma la contraseña del administrador del entorno actual. La clave de instalación/DPAPI se conserva. Las bases y bóvedas de cada modo quedan separadas, y al regresar reaparecen sus datos. No se convierten ni migran automáticamente cuentas de AD a locales. La primera visita al nuevo entorno inicializa su administrador con la misma contraseña; un destino existente con contraseña diferente impide el cambio. No cierres el programa durante una importación.

En modo local las cuentas integradas (RID inferior a 1000), miembros directos de Administradores, cuentas no locales y la cuenta Windows actual son **protegidas**: se visualizan, pero el backend bloquea cambios y las excluye de exportaciones. La pertenencia al grupo Administradores debe poder leerse; si falla se rechaza la operación. No se elimina ningún usuario ni se cambia pertenencia de cuentas existentes a grupos.

Importación/exportación cifrada y reautenticación funcionan en ambos modos. Para locales se compara la identidad de máquina, SID y PasswordLastSet antes de exportar/consultar una contraseña administrada. Contraseñas desconocidas o cambiadas fuera del gestor no pueden recuperarse. Entre servidores las cuentas locales tienen SID diferentes: se crea o restablece la cuenta de destino según la vista previa. Esto no migra permisos, perfiles, grupos ni derechos RDP; no implica que las cuentas sean una única identidad distribuida. El paquete conserva los identificadores criptográficos de versiones previas.

Dashboard/mapa leen el registro Security **del servidor instalado** tanto en local como en AD; requieren permisos de lectura y políticas de auditoría. No registran todos los servidores del dominio por seleccionar AD. RDP y firma siguen requiriendo certificados válidos y permisos Windows del usuario destino.
