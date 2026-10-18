Metakampo Access 1.9.1 permite administrar usuarios que ya están en el contenedor predeterminado de Active Directory.

- Admite CN=Users,DC=empresa,DC=local además de unidades organizativas existentes, sin mover cuentas.
- Configuración: «OU o contenedor de usuarios (DN)». Consulta y cambios siguen limitados a esa ubicación y sus descendientes, respetando permisos Windows y cuentas protegidas.
- Los errores identifican si requiere corrección el controlador DNS o el sufijo UPN.
- Prioriza los módulos oficiales de Windows PowerShell cuando existen rutas heredadas de PowerShell 7.
- Conserva protección IP en segundo plano y actualización firmada. Bóveda compartida, dashboard y vencimientos siguen requiriendo propietario abierto.

Después de actualizar, abre Configurar Metakampo Access con el propietario Windows original y establece la base real. Para las cuentas mostradas bajo CN=Users del dominio fresh.com: CN=Users,DC=fresh,DC=com. Conserva el controlador DNS y sufijo UPN válidos; confirma la contraseña administrativa actual. No hace falta mover usuarios ni crear otro dominio.

Las pruebas Windows utilizan un contrato AD simulado para validar el flujo de contenedores y los límites de edición, además de las pruebas nativas existentes e instalación/actualización. No sustituyen el piloto en un dominio real ni la validación directa en Windows Server 2019.
