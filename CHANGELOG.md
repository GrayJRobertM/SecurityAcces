# Cambios

## 1.10.1 — Carga de estilos en sesiones compartidas

- Reintenta abrir el canal local ocupado antes de enviar una solicitud, con plazo limitado y sin repetir operaciones enviadas; evita perder archivos durante cargas simultáneas.
- Declara CSS y JavaScript con tipos propios, aunque las asociaciones MIME del servidor sean incorrectas; conserva nosniff.
- Prueba de todos los CSS/scripts a través del canal compartido con asociaciones MIME incorrectas.
- La prueba de ventana instalada verifica todas las hojas de estilo y su aplicación real.
- Prueba nativa de 64 solicitudes concurrentes al canal local verificado.

## 1.10.0 — Servicio Windows y acceso único

- Servicio automático bajo identidad propietaria original y perfil DPAPI CurrentUser conservado.
- Activación única con diálogo Windows; credencial custodiada por SCM, sin archivos ni argumentos.
- Cliente del escritorio sin ventana propietaria; métricas y vencimientos en segundo plano.
- Actualizaciones firmadas desde cliente autorizado por SID propietario y credencial del gestor; parada/reinicio del servicio en instalador.

## 1.9.1 — Contenedores de usuarios Active Directory

- Admite bases CN=Users y OU sin mover cuentas; valida el tipo de objeto en Windows.
- Conserva límites de subárbol, protección de cuentas y grupos de departamento propios.
- AD usa Windows PowerShell de 64 bits y prioriza sus módulos oficiales para evitar conflictos con PowerShell 7.
- Distingue errores de controlador DNS y sufijo UPN en configuración.

## 2026-10-17 — 1.5.0 Administración compartida en sesiones RDP

- Contraseñas administrativas elegidas libremente sin mínimo ni complejidad obligatoria; política Windows/AD conservada.
- Cuentas individuales del gestor con administración completa, reautenticación propia y auditoría atribuida.
- Cliente sin elevación en cada escritorio RDP del mismo servidor; propietario central elevado conserva base y DPAPI.
- IPC local por named pipes con ACL restringida, rechazo de red y verificación del ejecutable servidor antes de enviar credenciales.
- Revocación de sesiones al desactivar/restablecer operadores; claves de Windows y permisos RDP no modificados.
- Paquetes RDP cifrados bajo identidad Windows del solicitante; la configuración sigue reservada a la ventana del propietario.
- Requiere mantener abierto el propietario; no se instala servicio ni se guardan credenciales Windows.

## 2026-10-16 — 1.4.1 Descripción independiente del departamento

- Corrige el mapeo incorrecto de Description en cuentas locales: departamento leído solo desde pertenencias a grupos MKD validados.
- Conserva Description al crear, editar e importar; muestra su valor por separado en Gestionar.
- Detecta varios departamentos y permite resolverlos explícitamente sin alterar grupos generales.
- Inventario y exportación no convierten descripciones en departamentos; AD conserva Department.

## 2026-10-16 — 1.4.0 Departamentos como grupos y elevación automática

- Grupos de departamento propios en SAM y AD; pertenencia idempotente y cambio de departamento sin adoptar grupos ajenos.
- Gestión de nombre/departamento/estado activo-inactivo desde el directorio y sincronización explícita de cuentas existentes con progreso y errores parciales.
- Contraseña conservada si el alta de cuenta tiene un fallo posterior de asignación al grupo.
- Manifiesto requireAdministrator para abrir con doble clic y confirmación UAC automática; identidad Windows/DPAPI conservadas.

## 2026-10-12 — Dashboard de uso y eventos Windows

- Dashboard inicial: accesos, fallos, usuarios y servidores, gráfica diaria y filtros de 7/30/90 días.
- Ingesta HTTPS de eventos normalizados con tokens por servidor, deduplicación y retención de 90 días.
- Recolector Windows con DPAPI, cursor, reintentos y avisos de brechas; despliegue Windows pendiente.
- 33 pruebas aprobadas; vista previa con datos ficticios separados de producción.


## 2026-10-12 — Clientes RDP

- Nueva sección Clientes RDP con historial y revocación de activaciones pendientes; acción directa desde el directorio de usuarios.
- Exportación de perfiles por servidor, puerto y usuario. Firma nativa de `.rdp` con `rdpsign /sha256` y firma Authenticode del lanzador con un certificado existente.
- Entrega cifrada de la contraseña vigente por HTTPS, código criptográfico de activación, vigencia de 30 minutos y consumo único serializado.
- Preparación de la credencial Windows mediante CredWriteW, sin contraseñas en argumentos de procesos ni en el ZIP exportado.
- Modo demo exporta únicamente un perfil sin firma y sin credenciales; no simula una firma válida.
- 23 pruebas automáticas aprobadas; firma Windows simulada en pruebas de servicio. Prueba nativa con certificado, Credential Manager y MSTSC pendiente en Windows.
- Revisión visual de esta ampliación pendiente: el navegador rechazó la inspección de la pestaña local debido a su política de URL. No se intentó eludir ese bloqueo.

## 2026-10-12 — Primera versión

- Directorio y adaptador AD; generación fuerte de 15 caracteres por defecto, bóveda cifrada y auditoría.
- Freshkampo DS v2.1, tema Fresa, con layout adaptable y modo oscuro.
# 1.0.0 · Aplicación independiente para Windows Server

- Ventana de escritorio local con asistente de configuración, acceso exclusivo y cierre del proceso con la ventana.
- Instalador x64 con Python y runtime WebView2 oficial incluido; no requiere portal publicado ni IIS.
- Clave/configuración con DPAPI, binding de equipo/SID, ACL privada, bóveda AES-256-GCM y contraseña administrativa elegida en el primer inicio.
- Lector del registro Security del servidor instalado y dashboard con recuperación de eventos disponibles hasta 90 días.
- Clientes RDP firmados con credenciales DPAPI utilizables solo en el mismo servidor y cuenta Windows, sin activación remota.
- Compilación, pruebas Windows, prueba de ventana WebView2, instalación y ejecutable congelado en GitHub Actions.
- Conexión al AD real y firma con certificados empresariales requieren validación en el servidor del usuario. MFA no incluido.

# 1.1.0 · Mapa de accesos

- Mapa mundial local con puntos por ubicación aproximada, zoom/desplazamiento y lista accesible de ubicaciones.
- Detalle de todas las cuentas, IPs, fechas y resultados al pulsar un punto, con paginación y filtros de cuenta/periodo/actividad.
- DB-IP City Lite (octubre 2026) y cartografía Natural Earth incluidos para consultas offline; sin enviar IPs ni usuarios a terceros.
- Orígenes privados/desconocidos fuera del mapa; intentos fallidos diferenciados de accesos y fallos de red diferenciados de RDP.
- Nueve pruebas adicionales de autenticación, filtros, IPv4/IPv6, ausencia de geolocalización, agrupación y paginación.

# 1.2.0 · Sincronización protegida de usuarios y contraseñas

- Importación/exportación desde el directorio con confirmación administrativa, vista previa y confirmación antes de aplicar.
- Archivo .fksync AES-256-GCM con clave de transferencia independiente; CSV reservado a atributos sin contraseñas.
- Contraseñas generadas/aplicadas por el gestor guardadas cifradas y verificadas contra la versión de replicación de AD; claves desconocidas o desactualizadas no se exportan.
- Sincronización local de secretos entre instancias del mismo AD sin restablecer cuando coinciden dominio, GUID y versión; archivos antiguos rechazados.
- Lotes de hasta 500 cuentas, control de colisiones, progreso e historial de resultados; sin eliminación, ampliación de grupos ni copia de claves maestras.
- Conserva el módulo de mapa offline de accesos.


# 1.2.1 · Marca Metakampo

- Nombre Metakampo Access en interfaz, asistente, ventanas, instalador y descargas.
- Icono M multicolor basado en la imagen del usuario en la interfaz, favicon y ejecutable/instalador Windows.
- Identificadores de instalación, rutas de datos y formatos cifrados conservados para actualizar sin perder compatibilidad.

# 1.3.0 · Usuarios locales y Active Directory

- Asistente con modos Usuarios locales, AD y Demostración; cambio con reautenticación y datos separados por entorno.
- Adaptador local SAM por SID: crear cuentas estándar, restablecer, habilitar/deshabilitar y desbloquear.
- Protección de cuentas integradas, administradores y cuenta actual; rechaza controladores de dominio y exige elevación para modo local.
- Sincronización cifrada y consulta de claves con detección de cambios de contraseña local; cuenta RDP EQUIPO\usuario.
- Lector Security, métricas y mapa activos en ambos modos reales.

# 1.3.1 · Detección de cuentas locales existentes

- Inventario directo de Windows visible sin elevación, con origen, equipo y total.
- Si falla la consulta de miembros de Administradores se conservan las cuentas en modo de solo lectura; las mutaciones siguen bloqueadas.
- Referencia estable de cuenta durante consultas ADSI opcionales; errores de consulta visibles en tabla.
- Detección explícita limpia filtros; importación de archivos diferenciada de la detección del servidor.
- Prueba nativa preserva cuentas anteriores y simula un fallo de resolución de Administradores.
- PowerShell de 64 bits por ruta absoluta, módulos estándar desde PSHOME y diagnóstico de fallos de arranque sin mostrar stderr ni credenciales.

# 1.3.2 · Inventario SAM sin consultas lentas por cuenta

- Retira WMI y consultas ADSI de bloqueo del inventario.
- Verifica Administradores por SID con NetLocalGroupGetMembers nivel 0, sin traducción de nombres de miembros.
- Mantiene salvaguardas, modo de solo lectura y límite de 45 segundos.
- Desbloqueo explícito para usuarios locales sin precargar su estado; duplicados generan un mensaje claro y HTTP 409.
- Prueba nativa bloquea WMI/resolución de nombres y comprueba listado en menos de 30 segundos.
