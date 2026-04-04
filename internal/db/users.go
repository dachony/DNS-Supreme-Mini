package db

import (
	"database/sql"
	"fmt"
	"time"
)

type User struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	FirstName    string    `json:"first_name"`
	LastName     string    `json:"last_name"`
	Email        string    `json:"email"`
	Role         string    `json:"role"`
	MFAEnabled   bool      `json:"mfa_enabled"`
	MFAType      string    `json:"mfa_type,omitempty"`
	MFASecret    string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	LastLogin    *time.Time `json:"last_login,omitempty"`
}

func (d *Database) CreateUser(u *User) error {
	now := time.Now().Format(time.RFC3339)
	result, err := d.db.Exec(`
		INSERT INTO users (username, password_hash, first_name, last_name, email, role, mfa_enabled, mfa_type, mfa_secret, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, u.Username, u.PasswordHash, u.FirstName, u.LastName, u.Email, u.Role, boolToInt(u.MFAEnabled), u.MFAType, u.MFASecret, now, now)
	if err != nil {
		return err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return err
	}
	u.ID = int(id)
	u.CreatedAt, _ = time.Parse(time.RFC3339, now)
	u.UpdatedAt = u.CreatedAt
	return nil
}

func scanUser(row interface{ Scan(dest ...any) error }) (*User, error) {
	u := &User{}
	var mfaEnabled int
	var createdStr, updatedStr string
	var lastLoginStr sql.NullString
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.FirstName, &u.LastName,
		&u.Email, &u.Role, &mfaEnabled, &u.MFAType, &u.MFASecret,
		&createdStr, &updatedStr, &lastLoginStr)
	if err != nil {
		return nil, err
	}
	u.MFAEnabled = mfaEnabled != 0
	u.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
	u.UpdatedAt, _ = time.Parse(time.RFC3339, updatedStr)
	if lastLoginStr.Valid && lastLoginStr.String != "" {
		t, err := time.Parse(time.RFC3339, lastLoginStr.String)
		if err == nil {
			u.LastLogin = &t
		}
	}
	return u, nil
}

func (d *Database) GetUserByUsername(username string) (*User, error) {
	row := d.db.QueryRow(`
		SELECT id, username, password_hash, first_name, last_name, email, role,
			mfa_enabled, mfa_type, mfa_secret, created_at, updated_at, last_login
		FROM users WHERE username = ?
	`, username)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

func (d *Database) GetUserByID(id int) (*User, error) {
	row := d.db.QueryRow(`
		SELECT id, username, password_hash, first_name, last_name, email, role,
			mfa_enabled, mfa_type, mfa_secret, created_at, updated_at, last_login
		FROM users WHERE id = ?
	`, id)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
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
		var createdStr, updatedStr string
		var lastLoginStr sql.NullString
		err := rows.Scan(&u.ID, &u.Username, &u.FirstName, &u.LastName, &u.Email,
			&u.Role, &mfaEnabled, &u.MFAType, &createdStr, &updatedStr, &lastLoginStr)
		if err != nil {
			continue
		}
		u.MFAEnabled = mfaEnabled != 0
		u.CreatedAt, _ = time.Parse(time.RFC3339, createdStr)
		u.UpdatedAt, _ = time.Parse(time.RFC3339, updatedStr)
		if lastLoginStr.Valid && lastLoginStr.String != "" {
			t, err := time.Parse(time.RFC3339, lastLoginStr.String)
			if err == nil {
				u.LastLogin = &t
			}
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

func (d *Database) CreatePasswordReset(userID int, token string, expiresAt time.Time) error {
	// Delete old unused tokens for this user
	d.db.Exec("DELETE FROM password_resets WHERE user_id = ? AND used = 0", userID)
	_, err := d.db.Exec(
		"INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)",
		userID, token, expiresAt.Format(time.RFC3339),
	)
	return err
}

func (d *Database) ValidateResetToken(token string) (int, error) {
	var userID int
	var expiresAtStr string
	var used int
	err := d.db.QueryRow(
		"SELECT user_id, expires_at, used FROM password_resets WHERE token = ?",
		token,
	).Scan(&userID, &expiresAtStr, &used)
	if err != nil {
		return 0, fmt.Errorf("invalid token")
	}
	if used != 0 {
		return 0, fmt.Errorf("token already used")
	}
	expiresAt, _ := time.Parse(time.RFC3339, expiresAtStr)
	if time.Now().After(expiresAt) {
		return 0, fmt.Errorf("token expired")
	}
	return userID, nil
}

func (d *Database) MarkResetTokenUsed(token string) {
	d.db.Exec("UPDATE password_resets SET used = 1 WHERE token = ?", token)
}

func (d *Database) GetUserByEmail(email string) (*User, error) {
	row := d.db.QueryRow(
		"SELECT id, username, password_hash, first_name, last_name, email, role, mfa_enabled, mfa_type, mfa_secret, created_at, updated_at, last_login FROM users WHERE email = ?",
		email,
	)
	u, err := scanUser(row)
	if err != nil {
		return nil, err
	}
	return u, nil
}
