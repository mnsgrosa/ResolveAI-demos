# ResolveAI Review Report

**Repository:** mnsgrosa/ResolveAI-demos
**PR:** #2
**Date:** 2026-04-07 02:07:03 UTC

## Summary

This diff introduces multiple critical security vulnerabilities including SQL injection, insecure session token generation using math/rand, and sensitive data exposure. Additionally, errors are silently ignored in the store layer, violating the repository's explicit error-handling patterns.

## Findings (8 total)

- 🔴 Critical: 4
- 🟡 Warning: 3
- 💡 Suggestion: 1

## Detailed Issues

### 1. 🔴 **Critical**

**File:** `auth/handler.go` (lines 17-18)

**Description:** SQL injection vulnerability: user-supplied 'username' and 'password' are interpolated directly into the query string using fmt.Sprintf. Use a prepared statement with placeholders instead: db.QueryRow("SELECT id FROM users WHERE username=$1 AND password=$2", username, password). This violates the repository's explicit security pattern requiring prepared statements.

**Suggested fix:**
```
row := db.QueryRow("SELECT id FROM users WHERE username=$1 AND password=$2", username, password)
```

*Replacing the fmt.Sprintf string interpolation with a parameterized query using positional placeholders prevents SQL injection by ensuring user-supplied values are treated as data, not executable SQL.*

### 2. 🔴 **Critical**

**File:** `auth/handler.go` (lines 31-38)

**Description:** Session tokens are generated using math/rand, which is not cryptographically secure. This violates the repository's explicit security pattern requiring crypto/rand for security-sensitive operations. Replace with crypto/rand.Read(b) to produce unpredictable tokens.

**Suggested fix:**
```
func generateSession() string {
	b := make([]byte, 16)
	_, err := crand.Read(b)
	if err != nil {
		panic("failed to generate secure session token: " + err.Error())
	}
	return fmt.Sprintf("%x", b)
}
```

*Replacing math/rand with crypto/rand.Read ensures the session token bytes are cryptographically unpredictable, eliminating the predictable-token vulnerability; the import alias 'crand "crypto/rand"' should be added and the 'math/rand' and 'time' imports removed.*

### 3. 🔴 **Critical**

**File:** `store/user.go` (lines 22-22)

**Description:** The error returned by rows.Scan() is silently ignored. This violates the repository's explicit pattern of always checking errors. A scan failure will leave 'u' partially or zero-valued and silently corrupt the result set. Change to: if err := rows.Scan(&u.ID, &u.Username, &u.Password); err != nil { return nil, fmt.Errorf("store: scan user: %w", err) }

**Suggested fix:**
```
package store

import (
	"database/sql"
	"fmt"
)

type User struct {
	ID       int
	Username string
	Password string
}

func GetAllUsers(db *sql.DB) ([]User, error) {
	rows, err := db.Query("SELECT id, username, password FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Password); err != nil {
			return nil, fmt.Errorf("store: scan user: %w", err)
		}
		users = append(users, u)
	}
	return users, nil
}
```

*Checking the error returned by rows.Scan() and propagating it prevents silently appending zero-valued or partially-populated User structs to the result slice when a scan fails.*

### 4. 🔴 **Critical**

**File:** `store/user.go` (lines 11-11)

**Description:** GetAllUsers fetches plaintext passwords from the database and exposes them in the returned User structs. Passwords should never be retrieved or stored in plaintext; only hashed values (e.g., bcrypt) should be stored, and the Password field should not be returned from a general-purpose listing function.

**Suggested fix:**
```
package store

import "database/sql"

type User struct {
	ID       int
	Username string
}

func GetAllUsers(db *sql.DB) ([]User, error) {
	rows, err := db.Query("SELECT id, username FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}
```

*Removes the Password field from the User struct and the SQL query so that plaintext passwords are never fetched from the database or exposed in the returned structs; also adds proper error handling for row scanning and iteration errors.*

### 5. 🟡 **Warning**

**File:** `auth/handler.go` (lines 31-32)

**Description:** rand.Seed(time.Now().UnixNano()) is deprecated since Go 1.20 and is not thread-safe when called concurrently. Even if math/rand were acceptable here (it is not), seeding should not be done inside the function. This is moot once crypto/rand is adopted.

**Suggested fix:**
```
func generateSession() string {
	b := make([]byte, 16)
	_, err := cryptorand.Read(b)
	if err != nil {
		panic(fmt.Sprintf("failed to generate secure random session token: %v", err))
	}
	return fmt.Sprintf("%x", b)
}
```

*Replacing math/rand with crypto/rand.Read removes the deprecated rand.Seed call, eliminates thread-safety concerns, and produces a cryptographically secure session token suitable for authentication use; the import should be updated to `cryptorand "crypto/rand"` and `math/rand` and `time` imports removed.*

### 6. 🟡 **Warning**

**File:** `auth/handler.go` (lines 27-27)

**Description:** The username is written directly into the HTTP response body via fmt.Fprintf. If the username contains HTML/script content this opens an XSS vector. Sanitize or encode output before writing to the response, and set an appropriate Content-Type header.

**Suggested fix:**
```
package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"html"
	"net/http"
)

var db *sql.DB

func Login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	var id int
	err := db.QueryRow("SELECT id FROM users WHERE username = ? AND password = ?", username, password).Scan(&id)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	token, err := generateSession()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("welcome " + html.EscapeString(username)))
}

func generateSession() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
```

*This fix addresses the XSS vulnerability by HTML-escaping the username before writing it to the response and setting a `text/plain` Content-Type header; it also replaces the SQL injection–prone `fmt.Sprintf` query with a parameterized query, replaces the cryptographically weak `math/rand`-based session token with `crypto/rand`, and adds `HttpOnly`/`SameSite` cookie flags for additional security.*

### 7. 🟡 **Warning**

**File:** `store/user.go` (lines 23-24)

**Description:** rows.Err() is not checked after the loop. Per the database/sql documentation, any iteration error is stored in rows.Err() and must be checked before returning results: if err := rows.Err(); err != nil { return nil, fmt.Errorf("store: iterate users: %w", err) }

**Suggested fix:**
```
func GetAllUsers(db *sql.DB) ([]User, error) {
	rows, err := db.Query("SELECT id, username, password FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Password); err != nil {
			return nil, fmt.Errorf("store: scan user: %w", err)
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate users: %w", err)
	}
	return users, nil
}
```

*Adding a check for rows.Err() after the loop ensures any iteration error is detected and returned, and the rows.Scan error is also now properly handled instead of being silently ignored.*

### 8. 💡 **Suggestion**

**File:** `auth/handler.go` (lines 26-26)

**Description:** The session cookie is missing Secure, HttpOnly, and SameSite attributes. Without HttpOnly the token is accessible to JavaScript; without Secure it may be sent over plain HTTP. Set these attributes: &http.Cookie{Name: "session", Value: token, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}.

**Suggested fix:**
```
http.SetCookie(w, &http.Cookie{Name: "session", Value: token, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
```

*Adding HttpOnly prevents JavaScript access to the cookie, Secure ensures it is only sent over HTTPS, and SameSite=Lax provides CSRF protection, together hardening the session cookie against common web attacks.*

---
*Generated by [ResolveAI](https://github.com/resolveAI)*