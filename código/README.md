# TFM v2 — PKI híbrida postcuántica: código y scripts

Ángel Olivares Perona. Código y scripts utilizados en el laboratorio v2 (bitácora, bloques 01–16).
Comentarios y mensajes de consola en inglés. Ningún fichero contiene claves ni contraseñas:
las apariciones de "password" son nombres de campo de la API REST de EJBCA o variables que
reciben una contraseña de inscripción aleatoria de un solo uso generada en tiempo de ejecución.

| Carpeta | Contenido | Dónde se instala | Bitácora |
|---|---|---|---|
| `00-paquetes-distribuidos/` | Los paquetes tal como se distribuyeron al laboratorio, con su `SHA256SUMS` (coinciden con los hashes comprobados en las VMs): `phc-client-v2-src.tgz` (bloque 11), `phc-client-v2.1-src.tgz` y `phc-client-v2.2-src.tgz` (bloque 13), `tfm-tests-12a.tgz`, `tfm-tests-12b.tgz`, `scripts-12.tgz` (bloque 12), `tfm-tests-13.tgz`, `tfm-tests-13b.tgz` y `scripts-13.tgz` (bloque 13; `scripts-13.tgz` incluye `13-chain-experiment.sh`, que no estaba en `tfm-tests-13b.tgz`), `phc-client-v2.3-src.tgz`, `phc-client-v2.3.1.patch`, `phc-client-v2.3.1-src.tgz`, `tfm-tests-14.tgz` y `scripts-14.tgz` (bloque 14; `scripts-14.tgz` es el estado final, con los cambios hechos en el laboratorio sobre `tfm-tests-14.tgz`), `tfm-tests-15.tgz` y `scripts-15.tgz` (bloque 15; ídem), `tfm-scale-16.tgz`, `tfm-scale-16b.tgz`, `tfm-scale-16c.tgz`, `phc-client-v2.4-src.tgz` y `scripts-16.tgz` (bloque 16) | — | 11–16 |
| `01-ca-emision/` | `sign_ejbca.sh` (núcleo Chimera/clásico: End Entity por CLI + REST `pkcs10enroll`), `sign_chimera.sh`, `sign_classic.sh` (envoltorios), `sign_composite.sh` (`openssl ca` con OpenSSL 3.4.0) | `ca:/home/ca/phc-certdist/` | Bloque 08 |
| `02-certdist/` | `certdist-server.c`, `certdist-client.c` (servicio de distribución de certificados sobre WireGuard) y la unidad `certdist.service` | Servidor en `ca:/home/ca/phc-certdist/`; cliente en cada nodo | Bloque 10 |
| `03-phc-client/` | `phc-client` v2.4 (CMake; v2.4 solo añade procesos paralelos a `phc-bench tls-server`): `libphccore` (`chimera.c`, `composite.c`, `phc_common.c`, `revocation.c`), `phc-verify`, `phc-msg`, `phc-file`, `phc-challenge` y `phc-bench`. La v2.2 usada en el bloque 13 está en `00-paquetes-distribuidos/` | Cada cliente (`~/phc-client`) y la imagen del bloque 16 | Bloques 11, 13, 14 y 16 |
| `04-pruebas-12-tamanos/` | Emisión y revocación de material de prueba, CRL, responder OCSP Composite (`setup_composite_ocsp.sh`, `ocsp-composite.service`), medición de tamaños de certificados, CRL y OCSP | `ca:/home/ca/tfm-tests/` | Bloque 12 |
| `06-wireguard/` | Plantillas de `wg0.conf` del servidor (CA, hub) y de los clientes, y `wg-tfm-host.conf` (el anfitrión como peer 10.10.0.4, bloque 16). Sin claves privadas: se generan en cada nodo con `wg genkey` y se insertan al escribir el fichero; las claves públicas son las del laboratorio | `/etc/wireguard/wg0.conf` | Bloque 09 |
| `05-pruebas-13-rendimiento/` | Lanzadores de `phc-bench` (primitivas, verificación, TLS), servidores de prueba, estadísticos y experimento de la política de cadena | Clientes (`~/tfm-tests/`) | Bloque 13 |
| `07-pruebas-14-revocacion/` | Revocación y publicación de CRL en la CA, sondeo de propagación OCSP/CRL, prueba de respuesta desfasada de `openssl ocsp`, servidor de sesión en caliente, servicio HTTP de la CRL Composite y análisis (`14-propagation.py`, `14-revcheck-stats.py`, `14-build-results.py`) | CA y clientes (`~/tfm-tests/`) | Bloque 14 |
| `08-pruebas-15-degradacion/` | Verificadores antiguo/nuevo frente a cada modelo, clientes TLS de tres generaciones frente a servidores de cada modelo, manipulación de certificados reales (`15-tamper.py`) y jerarquía Chimera de prueba con firma clásica válida (`Forge15.java`, BouncyCastle 1.84; las claves solo existen en memoria) | CA (`Forge15`) y clientes (`~/tfm-tests/`) | Bloque 15 |
| `09-pruebas-16-escala/` | Prueba de escala con contenedores: `Dockerfile` de la imagen de cliente, entrada del contenedor, driver (`16-scale.sh`), monitor de la CA, análisis y configuración (túnel del anfitrión sin claves, *drop-in* de WildFly) | Anfitrión (`b16/`) y CA | Bloque 16 |

Compilación de `phc-client` (en un nodo con el runtime PQC del bloque 06):

    cmake -S 03-phc-client -B 03-phc-client/build && cmake --build 03-phc-client/build

Compilación de `certdist`:

    gcc -O2 -Wall -Wextra -o certdist-server certdist-server.c
    gcc -O2 -Wall -Wextra -o certdist-client certdist-client.c

No incluido (vive en las VMs y se documenta en la bitácora): configuración de WildFly/EJBCA,
ficheros de propiedades de los Crypto Tokens, `composite-ca.cnf`, los `wg0.conf` reales
(contienen claves privadas; se incluyen solo plantillas) y la regla `sudoers` del bloque 08.
