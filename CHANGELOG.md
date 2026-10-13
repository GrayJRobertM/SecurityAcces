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
- Ocho pruebas adicionales de autenticación, filtros, IPv4/IPv6, ausencia de geolocalización, agrupación y paginación.

