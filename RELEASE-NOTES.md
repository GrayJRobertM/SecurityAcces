Metakampo Access 1.8.0 incorpora el módulo **Actualizaciones** para buscar y descargar nuevas versiones desde GitHub Releases. El propietario confirma la instalación con su contraseña; los clientes compartidos solo consultan el estado.

- Metadatos firmados RSA/SHA-256 y comprobación del instalador antes de ejecutarlo.
- Copia de seguridad de configuración cifrada y bases SQLite antes del cambio.
- Cierre de ventanas de Metakampo, pausa breve de monitores y reapertura con la misma cuenta Windows. Las sesiones RDP de Windows permanecen abiertas.
- Respeta las políticas de PowerShell y no reinicia Windows automáticamente.

**Primer uso:** instala esta versión manualmente una vez, sobre la instalación existente y con la misma cuenta Windows propietaria. Cierra las ventanas compartidas de versiones anteriores antes de instalar. Las siguientes versiones se gestionarán desde **Actualizaciones**.

El paquete incorpora firma de metadatos propia; no incluye certificado corporativo Authenticode. Las copias DPAPI siguen ligadas al equipo y al propietario. Consulta `DESKTOP.md` para requisitos, recuperación y publicación. Las pruebas automatizadas se realizan en Windows Server 2022; comprueba Windows Server 2019 en un piloto antes del despliegue general.
