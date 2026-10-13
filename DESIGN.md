# Adopción de Freshkampo DS v2.1

Tema único: Fresa, confirmado por el usuario el 12 de octubre de 2026. Base y tema en `static/tokens.css`; componentes en `static/app.css`. Se copiaron los tokens globales desde §13.2 y únicamente el bloque temático Fresa. El fallback de foco usa el primario Fresa.

- Patrón de navegación: sidebar + topbar en escritorio; navegación superior desplazable en móvil.
- Inter local con licencia OFL; fuente monoespaciada con fallback para las claves.
- Heroicons v2 mediante wrapper `icon()`; variante solid para navegación seleccionada y outline para las demás acciones. Íconos decorativos ocultos de lectores de pantalla.
- Espacios, radios, alturas, estados y sombras del sistema; controles mínimos de 44 px.
- Texto de estados con token `text.primary` sobre fondos semánticos suaves, para evitar depender del contraste de los colores sólidos de estado.
- Modo oscuro con primario Fresa y `onPrimary` oscuro; sin mezcla de temas.
- Labels visibles, foco visible, skip link, diálogos HTML nativos con captura de foco; bottom sheet en móvil; errores persistentes con texto; loading y empty en tablas y bóveda.
- Nuevos tokens de tamaño para sidebar, rail, contenedor, diálogo y login; dimensiones específicas del layout, no reemplazan la escala global.
- Acceso administrativo de una sola cuenta; grupos, MFA y roles son trabajo pendiente de integración, no controles simulados en la interfaz.

Validación visual: inicio de sesión, directorio, búsqueda, bóveda vacía, política y auditoría; pantallas móvil y escritorio. No se afirma certificación de accesibilidad ni una auditoría completa de seguridad de producción.

Extensión RDP: sección nueva con patrón de dos columnas, historial de activaciones y formulario de dos pasos para conexión y credenciales. Reutiliza tokens Fresa, controles de 44 px, iconografía Heroicons y estados de carga/vacío/error. Firma demo claramente diferenciada de firma real.

Dashboard: 4 KPIs, gráfica con paleta independiente oficial (§8.31.1), línea continua/punteada con etiquetas, ranking accesible con progress, tablas y filtros. Cobertura visible y demo explícita; actualizaciones con estado de error persistente. Mantiene el tema Fresa y usa tokens compartidos.

DS-EXCEPTION de alcance reducido: la serie 1 de gráficas en modo oscuro usa el token global `status.info` oscuro en lugar del azul fijo de la paleta, para mantener contraste gráfico sobre superficies oscuras. Las etiquetas y patrones siguen identificando las series. Revisión sugerida en 90 días.
