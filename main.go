package main

import (
	"context"
	"encoding/gob"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
)

// UserSessionData holds information we want to store in the session
type UserSessionData struct {
	UserID        string
	UserEmail     string
	UserName      string
	TenantID      string // e.g., "clientA_com" or "cybersecuritypilot_org"
	Authenticated bool
}

var (
	oauthConfig  *oauth2.Config
	log          = logrus.New()
	sessionStore *sessions.CookieStore // Will be initialized in init()
)

func init() {
	log.SetLevel(logrus.DebugLevel)
	file, err := os.OpenFile("server.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	log.SetOutput(file)

	gob.Register(&UserSessionData{})

	// --- Simplified Session Store Initialization ---
	// This expects SESSION_AUTH_KEY to be a 64-byte key (128 hex characters).
	// SESSION_ENC_KEY should be unset or empty for this to use AES-GCM.
	sessionAuthKeyString := os.Getenv("SESSION_AUTH_KEY")

	if sessionAuthKeyString == "" {
		log.Warn("SESSION_AUTH_KEY environment variable not set. USING INSECURE DEV DEFAULT. SET THIS FOR PRODUCTION.")
		// Default 64-byte key for development so AES-GCM is used.
		// NEVER USE THIS KEY IN PRODUCTION. GENERATE YOUR OWN.
		defaultAuthKey := "dev_only_64_byte_auth_key_for_aes_gcm_example_123456789012345" // Ensure this is 64 bytes
		if len(defaultAuthKey) != 64 {
			log.Fatal("FATAL: Developer error - default dev key is not 64 bytes.")
		}
		sessionStore = sessions.NewCookieStore([]byte(defaultAuthKey))
	} else {
		authKeyBytes := []byte(sessionAuthKeyString)
		if len(authKeyBytes) != 64 {
			log.Fatalf("FATAL: SESSION_AUTH_KEY must be 64 bytes long (128 hex characters) for AES-GCM. Current length: %d bytes.", len(authKeyBytes))
		}
		log.Info("Using 64-byte SESSION_AUTH_KEY for AES-GCM session encryption.")
		sessionStore = sessions.NewCookieStore(authKeyBytes)
	}

	if sessionStore == nil { // Should not happen with the logic above
		log.Fatal("FATAL: Session store failed to initialize.")
	}

	sessionStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7, // 7 days
		HttpOnly: true,
		Secure:   false, // Default to false for easier local dev. Set true in prod.
		SameSite: http.SameSiteLaxMode,
	}

	if os.Getenv("APP_ENV") == "production" {
		log.Info("Production environment (APP_ENV=production), setting session cookie to Secure=true.")
		sessionStore.Options.Secure = true
	} else {
		log.Info("Non-production environment or APP_ENV not set, session cookie Secure=false (allows HTTP).")
	}

	// Load OAuth config (using your hardcoded values for now to reduce variables)
	// !! Switch to ENV VARS for production for these as well !!
	oauthConfig = &oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		RedirectURL:  "https://www.cybersecuritypilot.org/oauth2callback", // Ensure this matches Google Console
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
}

func main() {
	http.HandleFunc("/", serveIndexOrDashboard)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/oauth2callback", handleCallback)
	http.HandleFunc("/dashboard", requireLogin(serveDashboard))
	http.HandleFunc("/logout", handleLogout)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	port := ":3000"
	log.Infof("Go server listening on %s", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func requireLogin(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := sessionStore.Get(r, "user-session")
		if err != nil {
			log.Warnf("Error getting session in requireLogin: %v. Redirecting to login.", err)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		userData, ok := session.Values["userData"].(*UserSessionData)
		if !ok || !userData.Authenticated {
			log.Info("User not authenticated in requireLogin. Redirecting to login.")
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		handler.ServeHTTP(w, r)
	}
}

func serveIndexOrDashboard(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, "user-session") // Ignore error, check content
	userData, ok := session.Values["userData"].(*UserSessionData)

	if ok && userData.Authenticated {
		log.Infof("User %s already logged in (session valid), redirecting to /dashboard", userData.UserEmail)
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	log.Infof("Serving main index.html (login page) for IP: %s", r.RemoteAddr)
	http.ServeFile(w, r, "index.html")
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	log.Infof("User clicked login from IP: %s", r.RemoteAddr)
	url := oauthConfig.AuthCodeURL("pseudo-state", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	log.Infof("Callback received. Request Host: %s, From IP: %s", r.Host, r.RemoteAddr)
	code := r.URL.Query().Get("code")
	if code == "" {
		log.Error("OAuth callback: Missing authorization code.")
		http.Error(w, "Authorization code missing.", http.StatusBadRequest)
		return
	}

	oauthToken, err := oauthConfig.Exchange(r.Context(), code)
	if err != nil {
		log.Errorf("Failed to exchange code for token: %v", err)
		http.Error(w, "Failed to exchange token.", http.StatusInternalServerError)
		return
	}

	idTokenString, ok := oauthToken.Extra("id_token").(string)
	if !ok || idTokenString == "" {
		log.Error("ID token not found in oauth token.")
		http.Error(w, "ID token missing.", http.StatusInternalServerError)
		return
	}

	payload, err := idtoken.Validate(context.Background(), idTokenString, oauthConfig.ClientID)
	if err != nil {
		log.Errorf("Failed to validate ID token: %v", err)
		http.Error(w, "Invalid ID token.", http.StatusUnauthorized)
		return
	}

	userEmail, _ := payload.Claims["email"].(string)
	userName, _ := payload.Claims["name"].(string)
	hostedDomain, hdOk := payload.Claims["hd"].(string)
	googleUserID := payload.Subject

	log.Infof("ID Token validated for user: %s (Email: %s, Name: %s, Hosted Domain 'hd': %s)",
		googleUserID, userEmail, userName, hostedDomain)

	var tenantIdentifierForPath string
	if hdOk && hostedDomain != "" {
		tenantIdentifierForPath = strings.ReplaceAll(hostedDomain, ".", "_")
		tenantIdentifierForPath = strings.ReplaceAll(tenantIdentifierForPath, "-", "_")
	} else {
		log.Infof("User %s is not from a Google Workspace. Using Google User ID for namespacing.", userEmail)
		if googleUserID == "" { // Should not happen if token is valid
			log.Error("Google User ID (payload.Subject) is empty after token validation.")
			http.Error(w, "Cannot determine unique user identifier.", http.StatusInternalServerError)
			return
		}
		tenantIdentifierForPath = "user_" + googleUserID
	}

	targetDirectoryPath := fmt.Sprintf("/var/www/html/userdata/%s", tenantIdentifierForPath)
	targetFilePath := fmt.Sprintf("%s/index.html", targetDirectoryPath)

	if _, statErr := os.Stat(targetDirectoryPath); os.IsNotExist(statErr) {
		log.Infof("Creating directory for tenant data '%s' at: %s", tenantIdentifierForPath, targetDirectoryPath)
		if mkdirErr := os.MkdirAll(targetDirectoryPath, 0755); mkdirErr != nil {
			log.Errorf("Failed to create directory %s: %v", targetDirectoryPath, mkdirErr)
			http.Error(w, "Failed to prepare user space.", http.StatusInternalServerError)
			return
		}
	} else if statErr != nil {
		log.Errorf("Error checking directory %s: %v", targetDirectoryPath, statErr)
		http.Error(w, "Failed to access user space.", http.StatusInternalServerError)
		return
	}

	log.Infof("Creating/updating placeholder index file for user %s (tenant dir %s) at: %s", userEmail, tenantIdentifierForPath, targetFilePath)
	file, createErr := os.Create(targetFilePath)
	if createErr != nil {
		log.Errorf("Failed to create file %s: %v", targetFilePath, createErr)
		http.Error(w, "Failed to create user page.", http.StatusInternalServerError)
		return
	}
	defer file.Close()
	fileContent := fmt.Sprintf("<html><body><h1>Content for %s (%s)</h1><p>Directory: %s</p><p><a href='/logout'>Sign Out</a></p></body></html>", userName, userEmail, tenantIdentifierForPath)
	if _, writeErr := file.WriteString(fileContent); writeErr != nil {
		log.Warnf("Failed to write content to file %s: %v", targetFilePath, writeErr)
	}


	session, err := sessionStore.Get(r, "user-session")
	if err != nil {
		log.Warnf("Could not get existing session, creating new. Error: %v", err)
	}

	sessionData := &UserSessionData{
		UserID:        googleUserID,
		UserEmail:     userEmail,
		UserName:      userName,
		TenantID:      tenantIdentifierForPath,
		Authenticated: true,
	}
	session.Values["userData"] = sessionData
	if err := session.Save(r, w); err != nil {
		log.Errorf("Failed to save session: %v", err) // This was the error point
		http.Error(w, "Failed to save session.", http.StatusInternalServerError)
		return
	}
	log.Infof("Session created for user %s, tenant ID %s", userEmail, tenantIdentifierForPath)

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func serveDashboard(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, "user-session")
	userData := session.Values["userData"].(*UserSessionData)

	log.Infof("Serving dashboard for user %s (TenantID: %s)", userData.UserEmail, userData.TenantID)
	contentFilePath := fmt.Sprintf("/var/www/html/userdata/%s/index.html", userData.TenantID)

	fileData, err := os.ReadFile(contentFilePath)
	if err != nil {
		log.Errorf("Failed to read content file %s for user %s: %v", contentFilePath, userData.UserEmail, err)
		http.Error(w, "Could not load your page content.", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "%s", string(fileData)) // Removed the extra sign out link from here as it's in the file now
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	session, err := sessionStore.Get(r, "user-session")
	if err == nil && session.Values["userData"] != nil { // Log only if there was something to log out
		log.Infof("Logging out user: %v", session.Values["userData"])
	} else if err != nil {
		log.Warnf("Error getting session during logout: %v", err)
	}


	session.Values["userData"] = &UserSessionData{} // Clear data
	session.Options.MaxAge = -1                 // Expire cookie immediately
	if err := session.Save(r, w); err != nil {
		log.Errorf("Error saving session during logout: %v", err)
	}
	http.Redirect(w, r, "/", http.StatusFound)
}
