package main

import (
	"crypto/rand"
	"encoding/json"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/andyleap/cajun"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jhunt/go-s3"
	"golang.org/x/crypto/bcrypt"
)

type wiki struct {
	client *s3.Client
}

type user struct {
	Password []byte
	Role     string
}

type session struct {
	username string
	role     string
	ttl      time.Time
}

var sessions = map[string]*session{}
var sessionMu = sync.Mutex{}

func main() {
	key, ok := os.LookupEnv("S3_KEY")
	if !ok {
		log.Fatal("Could not find S3_KEY, please ensure it is set.")
	}
	secret, ok := os.LookupEnv("S3_SECRET")
	if !ok {
		log.Fatal("Could not find S3_SECRET, please ensure it is set.")
	}
	domain, ok := os.LookupEnv("S3_DOMAIN")
	if !ok {
		log.Fatal("Could not find S3_DOMAIN, please ensure it is set.")
	}
	bucket, ok := os.LookupEnv("S3_BUCKET")
	if !ok {
		log.Fatal("Could not find S3_BUCKET, please ensure it is set.")
	}

	client, _ := s3.NewClient(&s3.Client{
		AccessKeyID:     key,
		SecretAccessKey: secret,
		Domain:          domain,
		Bucket:          bucket,
		UsePathBuckets:  true,
	})
	webauthn.New(&webauthn.Config{})

	w := &wiki{client: client}

	c := cajun.New()
	c.WikiLink = w

	templateFuncs := template.FuncMap{
		"render": func(path string) (string, error) {
			data, err := client.Get(path)
			if err != nil {
				return "", err
			}
			raw, err := io.ReadAll(data)
			if err != nil {
				return "", err
			}

			return string(raw), nil
		},
	}

	http.HandleFunc("GET /login", func(rw http.ResponseWriter, req *http.Request) {
		tmplData, err := client.Get("templates/login.html")
		if err != nil {
			panic(err)
		}
		tmplRaw, err := io.ReadAll(tmplData)
		if err != nil {
			panic(err)
		}
		tmpl, err := template.New("").Funcs(templateFuncs).Parse(string(tmplRaw))
		if err != nil {
			panic(err)
		}
		tmpl.Execute(rw, nil)
	})

	http.HandleFunc("POST /login", func(rw http.ResponseWriter, req *http.Request) {
		username := req.FormValue("username")
		password := req.FormValue("password")

		userData, err := client.Get("users/" + username)
		if err != nil {
			http.Error(rw, "Invalid username or password", http.StatusUnauthorized)
			return
		}
		userRaw, err := io.ReadAll(userData)
		if err != nil {
			panic(err)
		}
		var u user
		json.Unmarshal(userRaw, &u)
		if bcrypt.CompareHashAndPassword(u.Password, []byte(password)) != nil {
			http.Error(rw, "Invalid username or password", http.StatusUnauthorized)
			return
		}
		id := make([]byte, 32)
		rand.Read(id)
		sessionMu.Lock()
		defer sessionMu.Unlock()
		sessions[string(id)] = &session{
			username: username,
			role:     u.Role,
			ttl:      time.Now().Add(24 * time.Hour),
		}
		http.SetCookie(rw, &http.Cookie{
			Name:   "session",
			Value:  string(id),
			MaxAge: 86400,
		})
	})

	http.HandleFunc("/{page}", func(rw http.ResponseWriter, req *http.Request) {
		sidc, _ := req.Cookie("session")
		var s *session
		if sidc != nil {
			s = sessions[sidc.Value]
		}
		tmplData, err := client.Get("templates/view.html")
		if err != nil {
			panic(err)
		}
		tmplRaw, err := io.ReadAll(tmplData)
		if err != nil {
			panic(err)
		}
		tmpl, err := template.New("").Funcs(templateFuncs).Parse(string(tmplRaw))
		if err != nil {
			panic(err)
		}
		tmpl.Execute(rw, struct {
			Page    string
			Session *session
		}{
			req.PathValue("page"),
			s,
		})
	})

	http.HandleFunc("GET /{page}/edit", func(rw http.ResponseWriter, req *http.Request) {
		sidc, _ := req.Cookie("session")
		var s *session
		if sidc != nil {
			s = sessions[sidc.Value]
		} else {
			http.Redirect(rw, req, "/login", http.StatusFound)
			return
		}
		tmplData, err := client.Get("templates/edit.html")
		if err != nil {
			panic(err)
		}
		tmplRaw, err := io.ReadAll(tmplData)
		if err != nil {
			panic(err)
		}
		tmpl, err := template.New("").Funcs(templateFuncs).Parse(string(tmplRaw))
		if err != nil {
			panic(err)
		}
		tmpl.Execute(rw, struct {
			Page    string
			Session *session
		}{
			req.PathValue("page"),
			s,
		})
	})

	http.HandleFunc("POST /{page}/edit", func(rw http.ResponseWriter, req *http.Request) {
		sidc, _ := req.Cookie("session")
		var s *session
		if sidc != nil {
			s = sessions[sidc.Value]
		}
		if s != nil {
			http.Redirect(rw, req, "/login", http.StatusFound)
			return
		}
		up, err := client.NewUpload("pages/"+req.PathValue("page"), nil)
		if err != nil {
			panic(err)
		}
		content := req.FormValue("content")
		err = up.Write([]byte(content))
		if err != nil {
			panic(err)
		}
		err = up.Done()
		if err != nil {
			panic(err)
		}
		http.Redirect(rw, req, "/"+req.PathValue("page"), http.StatusFound)
	})

	http.ListenAndServe(":8080", nil)
}

func (w *wiki) WikiLink(href string, text string) string {
	_, err := w.client.Get("pages/" + href)
	if err != nil {
		return `<a href="` + href + `" class="free-link">` + text + `</a>`
	}
	return `<a href="` + href + `">` + text + `</a>`
}
