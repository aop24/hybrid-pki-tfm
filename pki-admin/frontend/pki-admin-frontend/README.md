# PKI Admin — Frontend

Frontend de demostración para administrar una PKI híbrida (Classic, Chimera y Composite).

## Requisitos
- Node.js 20 o superior
- npm

## Arranque
```bash
npm install
npm run dev
```
Vite mostrará la URL local, normalmente `http://localhost:5173`.

## Compilar
```bash
npm run build
npm run preview
```

## Estado
Solo frontend. Los datos son ficticios y las acciones de emisión/revocación son simulaciones: no se conecta a EJBCA, OpenSSL, OCSP, WireGuard ni certdist. La etiqueta DEMO ENVIRONMENT lo indica en la interfaz.
