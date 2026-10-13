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
