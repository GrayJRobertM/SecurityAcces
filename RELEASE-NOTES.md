Metakampo Access 1.9.0 corrige la comprobación del monitor e incorpora protección IP independiente de las sesiones Windows.

- «Comprobar monitor» muestra avance y resultado en una ventana, con errores específicos de archivos, credencial protegida o política PowerShell. No envía mensajes de prueba.
- Una tarea propia de Windows inicia la protección IP como SYSTEM al arrancar y continúa después de cerrar la aplicación o cerrar sesión. No necesita guardar contraseñas del propietario.
- La protección consulta directamente los fallos locales 4625 del periodo configurado, sin esperar a que el recolector del dashboard procese su historial.
- Conserva la política, lista blanca, reglas y alertas pendientes de la primera instalación propietaria al migrar al almacén compartido del servidor. Nunca mezcla políticas ya configuradas de otros perfiles.
- La lista blanca mantiene prioridad. Las alertas se generan tras confirmar el bloqueo; las notificaciones del monitor independiente de intentos no equivalen a una IP bloqueada.

En 1.8.0 puedes instalarla desde **Actualizaciones**. Al abrir por primera vez con el propietario original, revisa **Protección de IP**: debe mostrar proceso de segundo plano activo, política habilitada y lectura reciente de Security. Mantén incluidas las IP de administración en la lista blanca.

La bóveda, el dashboard y los vencimientos de cuentas conservan su funcionamiento anterior: el acceso compartido y esos monitores necesitan el propietario abierto. La tarea independiente cubre protección IP, vencimiento de sus bloqueos y sus avisos Telegram.

Instalador con metadatos RSA/SHA-256 verificados; sin certificado corporativo Authenticode. Piloto en Windows Server 2019 y entrega Telegram en el servidor real pendientes; las pruebas automatizadas se realizan en Windows Server 2022.
