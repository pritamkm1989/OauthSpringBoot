# OAuth2 with Keycloak & Spring Boot

A complete OAuth2/OpenID Connect implementation using **Keycloak** as the Identity Provider and **Spring Boot 3.3** as the resource server. This project demonstrates two authentication flows: **Browser Redirect (PKCE)** and **REST API Login (Direct Access Grant)** with **Role-Based Access Control (RBAC)**.

---

## Table of Contents

- [What is Keycloak?](#what-is-keycloak)
- [What is OAuth2 & OIDC?](#what-is-oauth2--oidc)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
  - [1. Start Keycloak](#1-start-keycloak)
  - [2. Configure Realm](#2-configure-realm)
  - [3. Create Users & Assign Roles](#3-create-users--assign-roles)
  - [4. Enable PKCE](#4-enable-pkce)
  - [5. Enable Userinfo for Roles](#5-enable-userinfo-for-roles)
  - [6. Start Spring Boot](#6-start-spring-boot)
- [Authentication Flows](#authentication-flows)
  - [Flow 1: Browser Redirect (Authorization Code + PKCE)](#flow-1-browser-redirect-authorization-code--pkce)
  - [Flow 2: REST API Login (Direct Access Grant)](#flow-2-rest-api-login-direct-access-grant)
- [API Reference](#api-reference)
- [Role-Based Access Control](#role-based-access-control)
- [How PKCE Works](#how-pkce-works)
- [Keycloak Realm Configuration](#keycloak-realm-configuration)
- [Project Structure](#project-structure)
- [Troubleshooting](#troubleshooting)

---

## What is Keycloak?

Keycloak is an open-source **Identity and Access Management (IAM)** solution. It provides:

- **Single Sign-On (SSO)** — authenticate once, access multiple applications
- **User Federation** — connect to LDAP/Active Directory
- **Identity Brokering** — social logins (Google, GitHub, etc.)
- **User Management** — admin console for managing users, roles, and permissions
- **Token Services** — issues JWT access tokens, refresh tokens, and ID tokens
- **OAuth2 & OpenID Connect** — full compliance with OAuth2 and OIDC standards

In this project, Keycloak acts as the **Authorization Server** that authenticates users and issues tokens.

---

## What is OAuth2 & OIDC?

### OAuth2 (Authorization Framework)
OAuth2 is a protocol that allows a third-party application to obtain limited access to a user's resources without exposing their credentials. It defines four grant types:

| Grant Type | Use Case |
|---|---|
| **Authorization Code** | Web apps (most secure for server-side apps) |
| **Authorization Code + PKCE** | SPAs & mobile apps (prevents code interception) |
| **Direct Access Grant (ROPC)** | Trusted server-side apps (username/password) |
| **Client Credentials** | Machine-to-machine (no user involved) |

### OpenID Connect (Identity Layer)
OIDC is a thin identity layer on top of OAuth2. It adds:
- **ID Token** — contains user identity claims (name, email, roles)
- **UserInfo Endpoint** — returns additional user profile information
- **Standard Scopes** — `openid`, `profile`, `email`, `roles`

### Tokens in This Project

| Token | Purpose | Where Used |
|---|---|---|
| **Access Token (JWT)** | Authorize API access. Contains roles in `realm_access.roles` and `resource_access` claims. | Sent as `Authorization: Bearer <token>` header |
| **Refresh Token** | Get new access tokens without re-login. | Sent to `/api/logout` to revoke |
| **ID Token** | Contains user identity claims. Used in browser redirect flow. | Read by Spring Security for OIDC login |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        CLIENTS                               │
│                                                              │
│   ┌─────────────┐              ┌──────────────────┐         │
│   │   Browser    │              │  REST Client      │         │
│   │  (PKCE Flow) │              │ (API Login Flow)  │         │
│   └──────┬───────┘              └────────┬─────────┘         │
│          │                               │                    │
│          │ GET /api/hello                │ POST /api/login    │
│          │ (session cookie)              │ {username,password} │
│          ▼                               ▼                    │
│   ┌──────────────────────────────────────────────────────┐   │
│   │              SPRING BOOT APP (port 9090)             │   │
│   │                                                      │   │
│   │  ┌─────────────────┐    ┌─────────────────────────┐ │   │
│   │  │  OIDC Login     │    │  JWT Resource Server    │ │   │
│   │  │  (PKCE + S256)  │    │  (Bearer Token Auth)   │ │   │
│   │  │  Session-based  │    │  Stateless              │ │   │
│   │  └────────┬────────┘    └───────────┬─────────────┘ │   │
│   │           │                         │                 │   │
│   │           │    ┌──────────────────┐ │                 │   │
│   │           │    │  RootController  │◄┘                 │   │
│   │           │    │  /api/login      │                   │   │
│   │           │    │  /api/hello      │                   │   │
│   │           │    │  /api/admin      │                   │   │
│   │           │    │  /api/user       │                   │   │
│   │           │    │  /api/me         │                   │   │
│   │           │    │  /api/logout     │                   │   │
│   │           │    └──────────────────┘                   │   │
│   └───────────┼──────────────────────────────────────────┘   │
│               │                                               │
└───────────────┼───────────────────────────────────────────────┘
                │
                │  OAuth2 / OIDC
                ▼
   ┌──────────────────────────────────────┐
   │     KEYCLOAK (port 8080)             │
   │                                      │
   │  Realm: spring-boot-test             │
   │                                      │
   │  Clients:                            │
   │  ├── spring-boot-authorization-code  │
   │  │   (Confidential, PKCE enabled)    │
   │  ├── spring-boot-client              │
   │  │   (Public)                        │
   │  └── spring-boot-client-credentials  │
   │      (Client Credentials)            │
   │                                      │
   │  Realm Roles:                        │
   │  ├── spring-boot-admin               │
   │  └── spring-boot-user                │
   │                                      │
   │  Client Roles (spring-boot-auth):    │
   │  └── user                            │
   └──────────────────────────────────────┘
```

---

## Prerequisites

- **Java 22+**
- **Docker** (for running Keycloak)
- **cURL** or **Postman** (for testing API endpoints)
- **Web browser** (for testing PKCE flow)

---

## Setup

### 1. Start Keycloak

```bash
docker-compose up -d
```

This starts Keycloak on `http://localhost:8080` with admin credentials `admin`/`admin`.

### 2. Configure Realm

Option A: Import the pre-configured realm:
1. Open `http://localhost:8080` → Admin Console
2. Click **Add Realm** → Import → Select `keyclock-realm.json`
3. Click **Create**

Option B: Create manually:
1. Create realm `spring-boot-test`
2. Create client `spring-boot-authorization-code` (Confidential)
3. Set redirect URI to `http://localhost:9090/*`
4. Enable **Standard Flow** and **Direct Access Grants**

### 3. Create Users & Assign Roles

1. In Keycloak Admin Console → **Users** → **Add User**
2. Create a user (e.g., `pritam`) with a password
3. Go to **Role Mappings** tab
4. Under **Available Roles**, select:
   - `spring-boot-admin` — for admin access
   - `spring-boot-user` — for user access
5. Click **Add selected**

### 4. Enable PKCE

1. Go to **Clients** → `spring-boot-authorization-code`
2. Scroll to **Advanced Settings**
3. Set **Proof Key for Code Exchange (PKCE)** to `S256`
4. Click **Save**

### 5. Enable Userinfo for Roles

For roles to appear in the userinfo response (needed for browser redirect flow):

1. Go to **Client Scopes** → `roles` → **Mappers** tab
2. Edit **"realm roles"** mapper → Enable **"Add to userinfo"** → Save
3. Edit **"client roles"** mapper → Enable **"Add to userinfo"** → Save

### 6. Start Spring Boot

```bash
./gradlew bootRun
```

The app starts on `http://localhost:9090/keycloak`

---

## Authentication Flows

### Flow 1: Browser Redirect (Authorization Code + PKCE)

This is the standard OAuth2 flow for web applications.

```
1. User opens http://localhost:9090/keycloak/api/hello in browser
2. Spring Security redirects to Keycloak login page
3. User enters credentials on Keycloak login page
4. Keycloak generates authorization code + PKCE challenge
5. Keycloak redirects back to Spring Boot with the code
6. Spring Boot exchanges code for tokens (including code_verifier)
7. Session is created, user can access protected endpoints
```

**Test in browser:**
```
http://localhost:9090/keycloak/api/hello
http://localhost:9090/keycloak/api/admin
http://localhost:9090/keycloak/api/user
```

### Flow 2: REST API Login (Direct Access Grant)

This is for programmatic access — no browser redirect needed.

```
1. Client sends POST /api/login with {username, password}
2. Spring Boot calls Keycloak token endpoint directly
3. Keycloak validates credentials and returns tokens
4. Client receives access_token + refresh_token
5. Client uses access_token in Authorization header for subsequent requests
```

**Test with cURL:**
```bash
# Step 1: Login
curl -X POST http://localhost:9090/keycloak/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"pritam","password":"your-password"}'

# Response:
# {
#   "accessToken": "eyJhbGciOiJSUzI1NiIs...",
#   "refreshToken": "dGhpcyBpcyBhIHJlZnJlc2g...",
#   "expiresIn": 300,
#   "tokenType": "Bearer"
# }

# Step 2: Use the token
curl http://localhost:9090/keycloak/api/hello \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."

# Response:
# {"message":"Hello","user":"pritam","roles":["spring-boot-user"]}

# Step 3: Logout (revoke refresh token)
curl -X POST http://localhost:9090/keycloak/api/logout \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"dGhpcyBpcyBhIHJlZnJlc2g..."}'
```

---

## API Reference

| Method | Endpoint | Auth Required | Description |
|---|---|---|---|
| `GET` | `/keycloak/open` | No | Public endpoint |
| `POST` | `/keycloak/api/login` | No | Login with username/password, returns JWT tokens |
| `POST` | `/keycloak/api/logout` | No | Revoke refresh token |
| `GET` | `/keycloak/api/hello` | Yes | Returns greeting with username and roles |
| `GET` | `/keycloak/api/admin` | Yes (`spring-boot-admin` role) | Admin-only endpoint |
| `GET` | `/keycloak/api/user` | Yes (`spring-boot-user` role) | User-only endpoint |
| `GET` | `/keycloak/api/client-secret` | Yes | Returns client info |
| `GET` | `/keycloak/api/me` | Yes | Returns full user profile and roles |

### Response Examples

**POST /api/login**
```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIs...",
  "refreshToken": "dGhpcyBpcyBhIHJlZnJlc2g...",
  "expiresIn": 300,
  "tokenType": "Bearer"
}
```

**GET /api/me** (with Bearer token)
```json
{
  "sub": "e1191ee5-df94-4188-9e40-26e583a964d7",
  "preferred_username": "pritam",
  "email": "pritam@example.com",
  "realm_roles": ["spring-boot-admin", "spring-boot-user"],
  "client_roles": {"spring-boot-authorization-code": {"roles": ["user"]}},
  "iss": "http://localhost:8080/realms/spring-boot-test"
}
```

**GET /api/admin** (with `spring-boot-admin` role)
```json
{
  "message": "Hello Admin",
  "user": "pritam",
  "roles": ["spring-boot-admin", "spring-boot-user"]
}
```

---

## Role-Based Access Control

### How It Works

1. **Keycloak** defines roles (realm roles + client roles)
2. Roles are included in the JWT token as claims:
   - Realm roles: `realm_access.roles` → `["spring-boot-admin", "spring-boot-user"]`
   - Client roles: `resource_access.{clientId}.roles` → `["user"]`
3. **Spring Security** extracts these roles from the JWT using a custom `JwtAuthenticationConverter`
4. Roles are mapped to Spring authorities with `ROLE_` prefix:
   - `spring-boot-admin` → `ROLE_spring-boot-admin`
   - `spring-boot-user` → `ROLE_spring-boot-user`
5. Controllers use `@PreAuthorize("hasRole('spring-boot-admin')")` to restrict access

### Available Roles

| Role | Type | Purpose |
|---|---|---|
| `spring-boot-admin` | Realm Role | Access `/api/admin` endpoint |
| `spring-boot-user` | Realm Role | Access `/api/user` endpoint |
| `user` | Client Role | Client-specific role |

### Access Matrix

| Endpoint | Required Role | Description |
|---|---|---|
| `/api/hello` | Any authenticated user | Public greeting |
| `/api/admin` | `spring-boot-admin` | Admin-only operations |
| `/api/user` | `spring-boot-user` | User-specific operations |
| `/api/me` | Any authenticated user | View own profile |

---

## How PKCE Works

PKCE (Proof Key for Code Exchange) protects the Authorization Code flow from interception attacks.

```
1. Client generates a random code_verifier (43-128 chars)
2. Client creates code_challenge = SHA256(code_verifier)
3. Client sends code_challenge + code_challenge_method=S256 to Keycloak
4. Keycloak stores the challenge, sends back an authorization code
5. Client sends code_verifier along with the code to exchange for tokens
6. Keycloak computes SHA256(code_verifier) and compares with stored challenge
7. If they match, tokens are issued
```

**Why PKCE matters:**
- Even if an attacker intercepts the authorization code, they cannot use it without the `code_verifier`
- PKCE is now recommended for ALL OAuth2 clients (not just public clients)

---

## Keycloak Realm Configuration

### Clients

| Client ID | Type | Flow | Description |
|---|---|---|---|
| `spring-boot-authorization-code` | Confidential | Auth Code + PKCE | Main client for this project |
| `spring-boot-client` | Public | Auth Code | Alternative public client |
| `spring-boot-client-credentials` | Confidential | Client Credentials | Service account (no user) |

### Protocol Mappers (roles scope)

| Mapper | Claim | Description |
|---|---|---|
| `realm roles` | `realm_access.roles` | Maps realm roles to JWT |
| `client roles` | `resource_access.{clientId}.roles` | Maps client roles to JWT |

---

## Project Structure

```
src/main/java/com/pkm/poc/Keycloak/
├── KeycloakApplication.java          # Spring Boot entry point
├── config/
│   └── SecurityConfig.java           # Security configuration (PKCE + JWT + RBAC)
├── controller/
│   └── RootController.java           # REST endpoints
├── dto/
│   ├── LoginRequest.java             # Login request DTO
│   └── LoginResponse.java            # Login response DTO
└── service/
    └── KeycloakTokenService.java     # Keycloak token endpoint client
```

### Key Dependencies

| Dependency | Purpose |
|---|---|
| `spring-boot-starter-oauth2-client` | OAuth2/OIDC client (browser redirect flow) |
| `spring-boot-starter-oauth2-resource-server` | JWT validation (API login flow) |
| `spring-boot-starter-security` | Spring Security core |
| `spring-boot-starter-web` | REST API support |
| `lombok` | Boilerplate reduction |

---

## Troubleshooting

### "Missing parameter: code_challenge_method"

**Cause:** PKCE not enabled in Keycloak.
**Fix:** Clients → `spring-boot-authorization-code` → Advanced Settings → PKCE = `S256`

### "no roles in received JWT"

**Cause:** `roles` scope not requested or userinfo not enabled for role mappers.
**Fix:**
1. Ensure `scope: openid,offline_access,profile,roles` in `application.yaml`
2. Enable "Add to userinfo" for realm roles and client roles mappers in Keycloak

### "401 Unauthorized" on API endpoints

**Cause:** Invalid or expired token.
**Fix:** Login again via `POST /api/login` to get a fresh access token.

### "403 Forbidden" on /api/admin or /api/user

**Cause:** User doesn't have the required role.
**Fix:** Assign the role in Keycloak Admin Console → Users → Role Mappings.

### Keycloak not starting

**Fix:** Ensure Docker is running and port 8080 is available:
```bash
docker ps
docker-compose logs keycloak
```

---

## License

This is a learning/demo project for understanding OAuth2 with Keycloak and Spring Boot.
