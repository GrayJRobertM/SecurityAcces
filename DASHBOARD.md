# Dashboard de uso y auditoría de Windows

El dashboard integra eventos de los servidores Windows supervisados, independientemente del cliente RDP utilizado. La vista previa usa exclusivamente datos ficticios señalados como DEMOSTRACIÓN. Las métricas reales requieren instalar el recolector en cada servidor y habilitar su auditoría.

## Qué mide

- Accesos correctos, intentos fallidos, usuarios únicos con accesos y servidores utilizados, durante 7, 30 o 90 días.
- Evolución diaria, los 10 usuarios y servidores con más accesos, y los últimos 50 eventos del ámbito seleccionado.
- Filtros por servidor y ámbito RDP o accesos interactivos/desbloqueos. Los días se agrupan usando el desplazamiento horario actual del navegador; para zonas con cambios estacionales históricos no equivale a una conversión completa por zona IANA.
- Estado de cada recolector: reportando, sin datos, sin señal reciente (más de 5 minutos) o revocado; avisos de brechas de cobertura notificadas por el recolector.
- Actualización de la vista cada minuto mientras esté visible; también se puede actualizar manualmente.

El registro administrativo del gestor se conserva separado de los eventos Windows. Generar o activar un paquete RDP no se cuenta como un acceso a Windows.

| Evento | Uso |
|---|---|
| 4624, tipo 10 | Acceso RDP correcto |
| 4625, tipo 10 | Intento fallido atribuido a RDP |
| 4624 / 4625, tipos 2, 7 y 11 | Accesos interactivos, desbloqueos y accesos con credenciales en caché, según el evento |
| 4625, tipo 3 | Fallo de red: se muestra aparte; puede corresponder a NLA u otro servicio. No se atribuye automáticamente a RDP |
| 4634 | Cierre de sesión, clasificado por tipo de acceso |
| 4778 / 4779, estación RDP-Tcp | Reconexión o desconexión RDP; no suma como nuevo acceso |

Estos indicadores cuentan eventos de acceso, **no horas de trabajo, duración de sesiones ni presencia actual**. No se infiere duración porque faltan cierres, pueden existir desconexiones sin cierre y deben correlacionarse las sesiones por equipo/arranque/Logon ID. Los eventos son telemetría reportada por un equipo autorizado, no evidencia inmutable ni certificación de identidad independiente.

## Instalación por servidor

1. Publica Freshkampo Access en modo `ad` mediante el portal HTTPS interno descrito en README. No se conecta directamente al controlador de dominio para extraer logins: cada servidor destino reporta sus eventos. Un controlador de dominio por sí solo no acredita todas las sesiones RDP.
2. En **Dashboard de uso → Registrar servidor**, indica nombre de recolector y nombre DNS del equipo. Confirma la contraseña administrativa. Copia el token que aparece una sola vez. El token solo permite enviar eventos bajo el servidor registrado; no permite leer la bóveda ni acceder al portal como administrador.
3. Copia `windows/Collect-Logons.ps1`, `windows/Set-CollectorSecret.ps1` y `windows/collector-config.example.json` al servidor. La política corporativa debe permitir o firmar estos scripts. No se requiere ni se incluye `ExecutionPolicy Bypass`.
4. Elige una identidad de servicio que pueda leer el canal **Security** y consultar eventos 1102 de borrado. Valida sus permisos con `Get-WinEvent -LogName Security -MaxEvents 1`; otorga únicamente los permisos necesarios conforme a la política de la empresa. Ser usuario de dominio no otorga automáticamente acceso a Security.
5. Crea una **carpeta nueva y dedicada** de datos, por ejemplo `C:\ProgramData\FreshkampoAccess\Collector`. Ejecuta bajo la misma identidad que utilizará el recolector:

```powershell
.\Set-CollectorSecret.ps1 -Directory 'C:\ProgramData\FreshkampoAccess\Collector'
```

El script pide el token sin mostrarlo, lo protege con DPAPI del usuario Windows actual y restringe la ACL de la carpeta a esa identidad. No uses esta operación sobre una carpeta compartida o existente con datos ajenos: sustituye su ACL. Configura por separado el acceso de respaldo/operación autorizado según la política empresarial. No guardes el token en argumentos, scripts, Git, notas o JSON.

6. Guarda `collector-config.json` dentro de esa carpeta, con el origen HTTPS y el nombre DNS **exactamente igual al registrado**. No contiene el token:

```json
{
  "portal": "https://access.empresa.local",
  "server": "srv-rdp.empresa.local"
}
```

7. Valida una ejecución bajo esa misma identidad:

```powershell
.\Collect-Logons.ps1 -ConfigPath 'C:\ProgramData\FreshkampoAccess\Collector\collector-config.json'
```

8. Para recolección continua (consulta cada 60 segundos, procesa el backlog en lotes de 100):

```powershell
.\Collect-Logons.ps1 -ConfigPath 'C:\ProgramData\FreshkampoAccess\Collector\collector-config.json' -Continuous -IntervalSeconds 60
```

Ejecuta este proceso mediante el mecanismo corporativo de servicio o tarea al inicio de Windows, con la misma identidad que protegió el token. **No se ha instalado una tarea ni servicio Windows automáticamente desde esta Mac.** Una invocación sin `-Continuous` procesa un lote y termina; debe ejecutarse periódicamente si se elige ese modo. No mantengas dos procesos para la misma carpeta: el script usa un bloqueo exclusivo.

9. Habilita mediante GPO la auditoría de **Logon**, **Logoff** y **Other Logon/Logoff Events**, con éxito y/o fallo según corresponda. Hazlo primero en un piloto; el recolector no modifica la GPO ni activa auditoría automáticamente.
10. Comprueba un acceso correcto, un fallo, una desconexión/reconexión y su aparición en el dashboard. Comprueba también corte de red, reintento, revocación y permisos. Los clientes locales, MSTSC u otros pueden generar eventos si Windows los registra; solo habrá cobertura de los servidores enrolados.

## Entrega, duplicados y cobertura

- Primera lectura: últimas 24 horas del registro Security. Después se usa un cursor persistente. Para histórico anterior necesitas un proceso de importación validado; esta versión no promete una carga inicial completa del registro.
- Solo se exportan campos normalizados (fecha, usuario/dominio, IP cuando exista, tipo, Logon ID, estado, estación y Record ID). No se exporta el XML completo ni el mensaje del evento.
- Token aleatorio por recolector; el backend guarda únicamente SHA-256 del token. La recepción exige HTTPS y token, incluso si se suministra una cookie administrativa. No admite llamadas desde un origen web.
- Lotes de hasta 500 eventos y 1 MiB; el script envía hasta 100. El backend valida todo el lote antes de escribir. Un error de lectura, POST o confirmación no adelanta el cursor.
- Reintentos deduplicados por fuente, servidor, canal Security implícito, generación del registro y Record ID. Al detectar borrado del registro se cambia y persiste la generación antes de enviar; se notifica una brecha. Si la retención local eliminó eventos aún no leídos se avisa de otra brecha.
- Cambiar el token no requiere borrar `collector-state.json`. Reinstalar el recolector y perder ese archivo puede producir una nueva generación y volver a contar histórico ya entregado; conserva y respalda el cursor. El sistema no deduplica por fecha/usuario porque eso eliminaría accesos legítimos repetidos.
- La telemetría se conserva **90 días**; se purga durante la recepción de lotes. No se agrega una automatización periódica independiente. Los metadatos de recolectores quedan en la base administrativa.
- Un heartbeat sin eventos mantiene la señal de recepción. Esto acredita entrega desde el recolector, no que todas las políticas de auditoría estén correctamente habilitadas. Verifica auditoría y tamaño/retención del registro Security.
- Revocar un recolector invalida su token para nuevas entregas, conservando el historial. Para renovar: revoca, registra de nuevo el mismo servidor y reemplaza el token protegido sin borrar el estado.
- Las claves, tokens y contraseñas no se muestran en métricas ni auditoría. El token del cliente queda protegido por DPAPI y ACL. La base contiene información de usuarios e IP; protege su acceso y respaldo como información empresarial.
- El registro y el recolector no resisten a un administrador que controle el equipo o la base; una fuente comprometida puede falsificar telemetría. No incluye firma por evento, WEF/SIEM, MFA del propio gestor ni almacenamiento externo inmutable.

## Validación realizada y pendiente

33 pruebas automáticas aprobadas, incluyendo separación demo/real, HTTPS, autenticación y alcance del recolector, deduplicación, generaciones, validación atómica, privacidad de tokens, clasificación de fallos NLA/red, filtros, grupos de días locales, revocación, heartbeat, brechas, retención y lotes grandes.

La vista previa visual permite revisar gráficos y filtros con datos ficticios. **El script PowerShell aún requiere un piloto en Windows** con permisos reales y eventos de Security. Desde esta Mac no se instalaron recolectores ni se recibieron accesos reales del dominio.

## Referencias

- [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent)
- [4624 y tipos de acceso](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624)
- [Auditoría de accesos y cierres](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/basic-audit-logon-events)
- [Otros eventos de acceso: 4778 y 4779](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-logonlogoff-events)
