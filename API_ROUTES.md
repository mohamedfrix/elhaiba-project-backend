# API Routes Documentation

This document describes the main API routes implemented in the backend, including authentication, quote management, and note management. Example requests are based on the working integration tests (`quote_handler_test.rs` and `user_handler_test.rs`).

---

## Authentication & User Routes

### POST `/users/login`
Authenticate a user and receive access/refresh tokens.

**Request Body:**
```json
{
  "email": "admin@example.com",
  "password": "changeme123"
}
```
**Response:**
```json
{
  "user": { ... },
  "tokens": {
    "access_token": "...",
    "refresh_token": "...",
    "expires_in": 900,
    "token_type": "Bearer"
  }
}
```

### POST `/users/refresh-token`
Obtain new tokens using a refresh token.

**Request Body:**
```json
{
  "refresh_token": "<refresh_token>"
}
```
**Response:**
```json
{
  "access_token": "...",
  "refresh_token": "...",
  "expires_in": 900,
  "token_type": "Bearer"
}
```

---

## Quote Routes

> All routes below (except POST `/quotes`) require an `Authorization: Bearer <access_token>` header from an admin user.

### POST `/quotes`
Create a new quote (public, multipart/form-data).

**Request:**
- Content-Type: `multipart/form-data`
- Fields:
  - `json`: JSON string of the quote object
  - `file1`, `file2`, ...: Optional files

### GET `/quotes`
List all quotes (admin only).

**Headers:**
```
Authorization: Bearer <access_token>
```

### PUT `/quotes/{id}/status`
Update the status of a quote (admin only).

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```
**Request Body:**
```json
{
  "status": "approved"
}
```

### GET `/quotes/{id}`
Get a single quote by ID (admin only).

**Headers:**
```
Authorization: Bearer <access_token>
```

---

## Quote Notes Routes

### POST `/quotes/notes`
Add a note to a quote (admin only).

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: application/json
```
**Request Body:**
```json
{
  "quote_id": "<quote_id>",
  "content": "Test note content"
}
```

### GET `/quotes/notes/{id}`
Get a single note by note ID (admin only).

**Headers:**
```
Authorization: Bearer <access_token>
```

### GET `/quotes/{quote_id}/notes`
List all notes for a quote (admin only).

**Headers:**
```
Authorization: Bearer <access_token>
```

---

## Error Handling
- All endpoints return appropriate HTTP status codes (200, 400, 401, 403, etc.).
- Error responses are JSON with a `message` field describing the error.

---

## Example: How to Use
1. **Login:**
   - POST `/users/login` to get tokens.
2. **Use Access Token:**
   - Add `Authorization: Bearer <access_token>` to all admin-protected requests.
3. **Refresh Token:**
   - POST `/users/refresh-token` with your refresh token to get new tokens.

---

For more details, see the integration tests in `tests/user_handler_test.rs` and `tests/quote_handler_test.rs`.
