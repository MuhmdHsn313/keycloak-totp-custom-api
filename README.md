# Shogun - Keycloak Custom TOTP Rest API

## Overview

This API documentation covers two custom Keycloak resources for user management and credential operations:

**MyResourceProvider**: Manages user credentials, including TOTP creation/deletion and password reset/update.
 
## MyResourceProvider API

### Endpoints

#### 1. Create TOTP

**Endpoint:** `POST /realms/{realm}/createTotp`

**Description:** Creates a TOTP (Time-based One-Time Password) credential for the user.

**Request Body:**
- `data` (JSON) - Contains the secret key for TOTP.

**Responses:**
- `200 OK` - TOTP created successfully.
- `409 Conflict` - TOTP already exists for the user.

#### 2. Delete TOTP

**Endpoint:** `DELETE /realms/{realm}/deleteTotp`

**Description:** Deletes the TOTP credential for the user.

**Form Parameters:**
- `code` (string) - TOTP code for validation.

**Responses:**
- `200 OK` - TOTP deleted successfully.
- `400 Bad Request` - Invalid TOTP code.


## Logging

Uses `JBossLog` for logging warnings and errors during the user registration, verification, and credential management processes.

## Security
- Requires user authentication for TOTP and password operations in `MyResourceProvider`.


## Installation
-  .\mvnw clean install 
