# Freshkampo Access · Aplicación Windows Server

Versión 1.0.0, x64. Instalador: **Freshkampo-Access-Setup-x64.exe**. Aplicación instalada: **FreshkampoAccess.exe**.

## Instalar y abrir

1. Usa Windows Server 2019, 2022 o 2025 x64 **con experiencia de escritorio**. Server Core no dispone de la interfaz requerida. Ejecuta el instalador como administrador; instala el programa, sus dependencias Python y el runtime oficial WebView2 incluido. No requiere Python, IIS, un portal publicado ni acceso a Internet para instalar. El instalador de esta primera entrega no tiene firma Authenticode empresarial.
2. Abre **Freshkampo Access** desde Inicio con la cuenta Windows que administrará la aplicación. Esa cuenta será propietaria de sus datos y debe conservarse. No hay contraseña administrativa predeterminada.
3. Elige **Demostración** para probar sin tocar AD, o **Active Directory** para operar con tu dominio. En AD necesitas RSAT Active Directory, el FQDN del controlador, el DN de la OU autorizada y el sufijo UPN. El asistente comprueba el módulo, el acceso al controlador y que la OU existe; no cambia cuentas como prueba de permisos.
4. Crea la contraseña de `admin`, con al menos 15 caracteres, mayúsculas, minúsculas, números y símbolos. Es distinta de la contraseña Windows. Inicia sesión en la aplicación con ella.
5. Para ajustar dominio/OU/certificados después, cierra el programa y abre **Configurar Freshkampo Access** desde Inicio. Debes confirmar la contraseña administrativa actual. Conserva el modo demo/AD de la instalación.

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

## Compilar y verificar

La rama `main` conserva el portal original. La rama `codex/windows-desktop` contiene esta versión. El workflow `.github/workflows/windows-desktop.yml` compila en Windows Server 2022, ejecuta pruebas, analiza sintaxis PowerShell, prueba el ejecutable congelado, compila el instalador y verifica instalación silenciosa y ejecutable instalado. El artefacto de GitHub Actions contiene el `.exe` y su SHA256. La verificación de integración en el dominio real, firma con tus certificados y conexión MSTSC debe realizarse en tu servidor.

Fuentes: [DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata), [pywebview](https://pywebview.flowrl.com/api/), [Inno Setup](https://jrsoftware.org/ishelp/), [WebView2](https://developer.microsoft.com/en-us/microsoft-edge/webview2/).
