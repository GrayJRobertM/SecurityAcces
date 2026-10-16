# Cambios

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
