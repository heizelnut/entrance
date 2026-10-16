package bastion

import (
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// waUser is the single bastion admin account.
type waUser struct {
	id    []byte
	name  string
	creds []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return u.id }
func (u *waUser) WebAuthnName() string                       { return u.name }
func (u *waUser) WebAuthnDisplayName() string                { return u.name }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (b *Bastion) waUser() (*waUser, error) {
	creds, err := b.st.Credentials()
	if err != nil {
		return nil, err
	}
	return &waUser{id: []byte("entrance-admin"), name: "admin", creds: creds}, nil
}

func (b *Bastion) setCeremonyCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name: ceremonyCookie, Value: id, Path: "/", HttpOnly: true,
		Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 300,
	})
}

// POST /webauthn/register/begin — start adding a passkey.
// Allowed with a valid session, or with the bootstrap token (first passkey).
func (b *Bastion) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if !b.authed(r) && !b.checkBootstrap(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	u, err := b.waUser()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	options, session, err := b.wa.BeginRegistration(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	b.setCeremonyCookie(w, b.putCeremony(*session))
	writeJSON(w, options)
}

// POST /webauthn/register/finish — complete passkey registration and log in.
func (b *Bastion) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if !b.authed(r) && !b.checkBootstrap(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	u, err := b.waUser()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session, ok := b.takeCeremony(r)
	if !ok {
		http.Error(w, "no pending registration", http.StatusBadRequest)
		return
	}
	cred, err := b.wa.FinishRegistration(u, session, r)
	if err != nil {
		http.Error(w, "registration failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := b.st.AddCredential(cred, "passkey"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sid, err := b.st.CreateSession(b.cfg.SessionTTL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	b.setSession(w, sid)
	b.log.Info("passkey registered", "remote", clientIP(r))
	writeJSON(w, map[string]any{"ok": true})
}

// POST /webauthn/login/begin — start a passkey login.
func (b *Bastion) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	has, err := b.st.HasCredentials()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !has {
		http.Error(w, "no passkey registered yet", http.StatusPreconditionRequired)
		return
	}
	u, err := b.waUser()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	options, session, err := b.wa.BeginLogin(u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	b.setCeremonyCookie(w, b.putCeremony(*session))
	writeJSON(w, options)
}

// POST /webauthn/login/finish — verify the assertion and open a session.
func (b *Bastion) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	u, err := b.waUser()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session, ok := b.takeCeremony(r)
	if !ok {
		http.Error(w, "no pending login", http.StatusBadRequest)
		return
	}
	cred, err := b.wa.FinishLogin(u, session, r)
	if err != nil {
		http.Error(w, "login failed: "+err.Error(), http.StatusUnauthorized)
		return
	}
	if err := b.st.UpdateCredential(cred); err != nil {
		b.log.Warn("update credential", "err", err)
	}
	sid, err := b.st.CreateSession(b.cfg.SessionTTL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	b.setSession(w, sid)
	b.log.Info("passkey login", "remote", clientIP(r))
	writeJSON(w, map[string]any{"ok": true})
}

// POST /logout — drop the browser session.
func (b *Bastion) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = b.st.DeleteSession(c.Value)
	}
	b.clearSession(w)
	writeJSON(w, map[string]any{"ok": true})
}

var _ = time.Minute // keep time import if unused in future edits
