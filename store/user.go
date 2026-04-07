package store

import "database/sql"

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
		rows.Scan(&u.ID, &u.Username, &u.Password)
		users = append(users, u)
	}
	return users, nil
}