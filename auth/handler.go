package auth

import (
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"time"
)

var db *sql.DB

func Login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	query := fmt.Sprintf("SELECT id FROM users WHERE username='%s' AND password='%s'", username, password)
	row := db.QueryRow(query)

	var id int
	err := row.Scan(&id)
	if err != nil {
		w.WriteHeader(401)
		return
	}

	token := generateSession()
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token})
	fmt.Fprintf(w, "welcome %s", username)
}

func generateSession() string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, 16)
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return fmt.Sprintf("%x", b)
}