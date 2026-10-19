Metakampo Access 1.10.0 incorpora un servicio Windows para abrir la aplicación desde un único acceso, sin mantener una ventana propietaria ni una sesión RDP abierta.

- Metakampo Access abre el cliente y, si falta la activación inicial, guía su configuración. La primera vez solicita elevación y la contraseña Windows del propietario en un diálogo nativo. No es la contraseña de admin del gestor.
- El servicio arranca automáticamente con Windows bajo la misma cuenta propietaria. Windows SCM custodia su credencial; no se incluye en archivos, argumentos, configuración de Metakampo ni instalador.
- Conserva la bóveda y la configuración DPAPI CurrentUser existentes, en su ubicación original. No cambia la identidad con permisos delegados de Active Directory ni mueve cuentas.
- Dashboard, vencimiento de cuentas y avisos se procesan desde el servicio; protección IP conserva su tarea independiente. El acceso continúa limitado al servidor instalado mediante canal local verificado.
- Las actualizaciones firmadas se pueden gestionar desde el cliente, como admin de Metakampo y desde la cuenta Windows propietaria original. El instalador detiene y reinicia el servicio existente conservando la credencial Windows.
- Configurar Metakampo Access queda como herramienta administrativa para cambios de entorno. La apertura habitual ya no requiere abrir Administrar servidor Metakampo.

Actualiza con la cuenta Windows propietaria original, cierra la ventana antigua y abre Metakampo Access. Completa una sola vez la activación del servicio con la contraseña Windows de esa cuenta. Si esa contraseña cambia o una GPO impide iniciar como servicio, hay que actualizar/revisar la credencial o política Windows; no se desactiva UAC ni se eluden las políticas del sistema.

Pruebas de servicio en Windows Server 2022 con cuenta aislada: SCM, sesión 0, DPAPI y bóveda conservados, trabajadores de fondo, cliente WebView2 sin GUI propietaria y parada/reinicio/reparación. Active Directory real, Telegram real y Windows Server 2019 directo requieren piloto en el entorno del usuario.
