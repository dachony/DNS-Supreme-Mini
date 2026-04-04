package db

import (
	"database/sql"
	"fmt"
	"time"
)

type User struct {
	ID           int        `json:"id"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"-"`
	FirstName    string     `json:"first_name"`
	LastName     string     `json:"last_name"`
	Email        string     `json:"email"`
	Role         string     `json:"role"`
	MFAEnabled   bool       `json:"mfa_enabled"`
	MFAType      string     `json:"mfa_type,omitempty"`
	MFASecret    string     `json:"-"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastLogin    *time.Time `json:"last_login,omitempty"`
}

func (d *Database) CreateUser(u *User) error {
	result, err := d.db.Exec(`
		INSERT INTO users (username, password_hash, first_name, last_name, email, role, mfa_enabled, mfa_type, mfa_secret)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, u.Username, u.PasswordHash, u.FirstName, u.LastName, u.Email, u.Role, boolToInt(u.MFAEnabled), u.MFAType, u.MFASecret)
	if err != nil {
		return err
	}
	id, _ := result.LastInsertId()
	u.ID = int(id)
	u.CreatedAt = time.Now()
	u.UpdatedAt = time.Now()
	return nil
}

func (d *Database) GetUserByUsername(username string) (*User, error) {
	u := &User{}
	var mfaEnabled int
	var lastLogin sql.NullString
	var createdAt, updatedAt string
	err := d.db.QueryRow(`
		SELECT id, username, password_hash, first_name, last_name, email, role,
			mfa_enabled, mfa_type, mfa_secret, created_at, updated_at, last_login
		FROM users WHERE username = ?
	`, username).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.FirstName, &u.LastName,
		&u.Email, &u.Role, &mfaEnabled, &u.MFAType, &u.MFASecret,
		&createdAt, &updatedAt, &lastLogin)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.MFAEnabled = mfaEnabled != 0
	u.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	u.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	if lastLogin.Valid {
		t, _ := time.Parse(time.RFC3339, lastLogin.String)
		u.LastLogin = &t
	}
	return u, nil
}

func (d *Database) GetUserByID(id int) (*User, error) {
	u := &User{}
	var mfaEnabled int
	var lastLogin sql.NullString
	var createdAt, updatedAt string
	err := d.db.QueryRow(`
		SELECT id, username, password_hash, first_name, last_name, email, role,
			mfa_enabled, mfa_type, mfa_secret, created_at, updated_at, last_login
		FROM users WHERE id = ?
	`, id).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.FirstName, &u.LastName,
		&u.Email, &u.Role, &mfaEnabled, &u.MFAType, &u.MFASecret,
		&createdAt, &updatedAt, &lastLogin)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.MFAEnabled = mfaEnabled != 0
	u.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	u.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	if lastLogin.Valid {
		t, _ := time.Parse(time.RFC3339, lastLogin.String)
		u.LastLogin = &t
	}
	return u, nil
}

func (d *Database) ListUsers() ([]User, error) {
	rows, err := d.db.Query(`
		SELECT id, username, first_name, last_name, email, role,
			mfa_enabled, mfa_type, created_at, updated_at, last_login
		FROM users ORDER BY id
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]User, 0)
	for rows.Next() {
		var u User
		var mfaEnabled int
		var lastLogin sql.NullString
		var createdAt, updatedAt string
		err := rows.Scan(&u.ID, &u.Username, &u.FirstName, &u.LastName, &u.Email,
			&u.Role, &mfaEnabled, &u.MFAType, &createdAt, &updatedAt, &lastLogin)
		if err != nil {
			continue
		}
		u.MFAEnabled = mfaEnabled != 0
		u.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
		u.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
		if lastLogin.Valid {
			t, _ := time.Parse(time.RFC3339, lastLogin.String)
			u.LastLogin = &t
		}
		users = append(users, u)
	}
	return users, nil
}

func (d *Database) UpdateUser(u *User) error {
	_, err := d.db.Exec(`
		UPDATE users SET first_name=?, last_name=?, email=?, role=?, updated_at=datetime('now')
		WHERE id=?
	`, u.FirstName, u.LastName, u.Email, u.Role, u.ID)
	return err
}

func (d *Database) UpdateUserPassword(id int, hash string) error {
	_, err := d.db.Exec(`UPDATE users SET password_hash=?, updated_at=datetime('now') WHERE id=?`, hash, id)
	return err
}

func (d *Database) UpdateUserMFA(id int, enabled bool, mfaType, secret string) error {
	_, err := d.db.Exec(`
		UPDATE users SET mfa_enabled=?, mfa_type=?, mfa_secret=?, updated_at=datetime('now')
		WHERE id=?
	`, boolToInt(enabled), mfaType, secret, id)
	return err
}

func (d *Database) UpdateLastLogin(id int) error {
	_, err := d.db.Exec(`UPDATE users SET last_login=datetime('now') WHERE id=?`, id)
	return err
}

func (d *Database) DeleteUser(id int) error {
	result, err := d.db.Exec(`DELETE FROM users WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

func (d *Database) SetRecoveryCodes(userID int, codes string) error {
	_, err := d.db.Exec("UPDATE users SET recovery_codes = ?, updated_at = datetime('now') WHERE id = ?", codes, userID)
	return err
}

func (d *Database) GetRecoveryCodes(userID int) string {
	var codes string
	d.db.QueryRow("SELECT COALESCE(recovery_codes, '') FROM users WHERE id = ?", userID).Scan(&codes)
	return codes
}

func (d *Database) UserCount() int {
	var count int
	d.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count
}

func (d *Database) GetUserByEmail(email string) (*User, error) {
	u := &User{}
	var mfaEnabled int
	var lastLogin sql.NullString
	var createdAt, updatedAt string
	err := d.db.QueryRow(
		"SELECT id, username, password_hash, first_name, last_name, email, role, mfa_enabled, mfa_type, mfa_secret, created_at, updated_at, last_login FROM users WHERE email = ?",
		email,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.FirstName, &u.LastName, &u.Email, &u.Role, &mfaEnabled, &u.MFAType, &u.MFASecret, &createdAt, &updatedAt, &lastLogin)
	if err != nil {
		return nil, err
	}
	u.MFAEnabled = mfaEnabled != 0
	u.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	u.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)
	if lastLogin.Valid {
		t, _ := time.Parse(time.RFC3339, lastLogin.String)
		u.LastLogin = &t
	}
	return u, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
