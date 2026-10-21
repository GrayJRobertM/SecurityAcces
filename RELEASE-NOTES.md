Metakampo Access 1.10.1 corrige la carga de estilos en sesiones compartidas. Conserva el diseño y los controles de seguridad existentes.

El cliente reintenta abrir el canal local cuando está ocupado por otras solicitudes simultáneas, dentro de un plazo limitado. El reintento se realiza antes de enviar una operación; no repite cambios ya enviados ni reduce la verificación del ejecutable, los permisos o la identidad del usuario. Una prueba nativa comprueba 64 solicitudes concurrentes.

La aplicación declara los tipos de sus archivos CSS y JavaScript, sin modificar el registro de Windows ni desactivar nosniff. La prueba del cliente instalado comprueba que todas las hojas de estilo se apliquen dentro de WebView2, además de cargar el acceso.

Instala sobre la versión existente con la cuenta Windows propietaria original, sin desinstalar antes. Conserva el servicio y los datos de 1.10.0. Si la comprobación automática falla por HTTPS, utiliza el enlace estable del instalador; esta corrección de estilos no resuelve por sí sola fallos de red, proxy o certificados.

Active Directory real, Telegram real y Windows Server 2019 directo requieren validación en el entorno del usuario.
