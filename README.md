# Hybrid PKI TFM — Source Code

Source code repository associated with the Master's Thesis on a hybrid classical and post-quantum Public Key Infrastructure (PKI).

## Contents

- `codigo/01-emision/`: certificate issuance and signing scripts.
- `codigo/02-wireguard/`: WireGuard configuration templates.
- `codigo/03-certdist/`: certificate distribution service and client.
- `codigo/04-phc-client/`: C implementation of the hybrid client, verification components, and auxiliary tools.
- `codigo/05-tamanos/`: experiments involving certificate, CRL, and OCSP sizes.
- `codigo/06-rendimiento/`: performance and TLS experiments.
- `codigo/07-revocacion/`: certificate revocation and OCSP/CRL propagation experiments.
- `codigo/08-degradacion/`: compatibility, manipulation, and downgrade testing.
- `codigo/09-escala/`: automation and scalability test analysis.
- `pki-admin/`: web-based administration and monitoring dashboard for the hybrid PKI infrastructure. It includes a FastAPI backend for integration with EJBCA and the Composite PKI, and a React, TypeScript, and Vite frontend for querying and managing information about certification authorities and certificates.

## PKI Administration Dashboard

The `pki-admin/` directory contains a web application that provides a centralized interface for querying the status and information of the PKI infrastructure.

The application is divided into two components:

- **Backend (`pki-admin/backend/`)**: REST API developed with FastAPI and Python. It integrates with EJBCA and provides access to information from the Composite PKI.
- **Frontend (`pki-admin/frontend/pki-admin-frontend/`)**: web interface developed with React, TypeScript, and Vite, allowing users to visualize certification authorities and certificates across the different PKI models.

The application supports the Classic, Chimera, and Composite models, providing a unified view of certificates managed by the different infrastructures.

Running the dashboard requires configuring the connections to EJBCA, the authentication certificate paths, and the Composite PKI directories. Configuration parameters are documented in `pki-admin/backend/.env.example`.

## Security Notice

This package contains source code and configuration templates, not private keys or access credentials intentionally. Before making the repository public, review configuration values, IP addresses, hostnames, identifiers, and any other information that could disclose details about the laboratory environment. Replace environment-specific values with variables or examples whenever necessary.

Do not add private keys, personal certificates, passwords, tokens, `.env` files, or copies of data directories. WireGuard templates contain placeholders and must be completed locally using keys generated for each device.

The `pki-admin` dashboard also requires credentials and certificates to connect to EJBCA. These must be configured locally and must never be included in the repository.

## Requirements and Reproducibility

Specific requirements depend on the experiment. Refer to the comments in each script and to the included `CMakeLists.txt`, `Dockerfile`, and service unit files. The laboratory configuration (EJBCA, OpenSSL/oqs-provider, WireGuard, addresses, and paths) must be adapted to the environment in which the experiments are reproduced.

The PKI administration dashboard requires Python and the dependencies listed in `pki-admin/backend/requirements.txt`, as well as Node.js and npm to install the frontend dependencies using `package.json` and `package-lock.json`.

The laboratory configuration and credentials required to connect to EJBCA and the Composite PKI must be configured locally before running the application.

## Scope

This repository contains the source code developed and used for the Master's Thesis. Experimental results and the methodological discussion are documented in the thesis manuscript. The exact version associated with the final submission should be identified using a Git tag (for example, `v1.0-tfm`).
