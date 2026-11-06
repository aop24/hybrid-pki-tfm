# Hybrid PKI TFM — código fuente

Repositorio de código asociado al Trabajo Fin de Máster sobre una PKI híbrida clásica y postcuántica.

## Contenido

- `codigo/01-emision/`: scripts de emisión y firma de certificados.
- `codigo/02-wireguard/`: plantillas de configuración de WireGuard.
- `codigo/03-certdist/`: servicio y cliente de distribución de certificados.
- `codigo/04-phc-client/`: implementación en C del cliente híbrido, verificadores y herramientas auxiliares.
- `codigo/05-tamanos/`: experimentos de tamaños de certificados, CRL y OCSP.
- `codigo/06-rendimiento/`: experimentos de rendimiento y TLS.
- `codigo/07-revocacion/`: experimentos de revocación y propagación OCSP/CRL.
- `codigo/08-degradacion/`: pruebas de compatibilidad, manipulación y degradación.
- `codigo/09-escala/`: automatización y análisis de pruebas de escalabilidad.

## Aviso de seguridad

Este paquete contiene código y plantillas, no claves privadas ni credenciales de acceso deliberadamente. Antes de publicar el repositorio como público, revisa los valores de configuración, direcciones IP, nombres de host, identificadores y cualquier dato que pueda revelar información de tu laboratorio. Sustituye los valores específicos del entorno por variables o ejemplos cuando sea necesario.

No añadas claves privadas, certificados personales, contraseñas, tokens, ficheros `.env` ni copias de directorios de datos. Las plantillas de WireGuard contienen marcadores de posición y deben completarse localmente con claves generadas para cada equipo.

## Requisitos y reproducción

Los requisitos concretos dependen del experimento. Consulta los comentarios de cada script y los ficheros `CMakeLists.txt`, `Dockerfile` y unidades de servicio incluidos. La configuración de laboratorio (EJBCA, OpenSSL/oqs-provider, WireGuard, direcciones y rutas) debe adaptarse al entorno de quien reproduzca las pruebas.

## Alcance

Este repositorio recoge el código fuente desarrollado y utilizado en el TFM. Los resultados experimentales y la explicación metodológica se documentan en la memoria. La versión exacta asociada a la entrega final debe identificarse mediante una etiqueta Git (por ejemplo, `v1.0-tfm`).
