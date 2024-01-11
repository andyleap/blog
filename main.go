package main

import (
	"crypto/rand"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"github.com/andyleap/cajun"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jhunt/go-s3"
	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"
)

type Page struct {
	Slug    string `db:"slug"`
	Content string `db:"content"`
}

type User struct {
	ID       int    `db:"id" identity:"true" unique:"true"`
	Username string `db:"username"`
	Password string `db:"password"`
}

type Session struct {
	ID     string `db:"id"`
	UserID int    `db:"user_id" relation:"user.id"`
}

type Template struct {
	Name    string `db:"name"`
	Content string `db:"content"`
}

var am = &AutoMigrate{
	Tables: map[string]interface{}{},
}

func init() {
	am.AddTable("page", Page{})
	am.AddTable("user", User{})
	am.AddTable("session", Session{})
	am.AddTable("template", Template{})
}

type wiki struct {
	client *s3.Client
	db     *sqlx.DB
}

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

	db, err := sqlx.Connect("pgx", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}

	w := &wiki{
		client: client,
		db:     db,
	}

	if err := am.Migrate(db); err != nil {
		log.Fatal(err)
	}

	c := cajun.New()
	c.WikiLink = w

	templateFuncs := template.FuncMap{
		"render": func(path string) (template.HTML, error) {
			var page Page
			err := w.db.Get(&page, "SELECT * FROM page WHERE slug = $1", path)
			if err != nil {
				return template.HTML(fmt.Sprintf("%q not found", path)), nil
			}
			out, err := c.Transform(page.Content)
			return template.HTML(out), err
		},
		"getRaw": func(path string) (string, error) {
			var page Page
			err := w.db.Get(&page, "SELECT * FROM page WHERE slug = $1", path)
			if err != nil {
				return fmt.Sprintf("%q not found", path), nil
			}
			return string(page.Content), nil
		},
	}

	runTemplate := func(name string, rw http.ResponseWriter, data interface{}) {
		var tmpl Template
		err := w.db.Get(&tmpl, "SELECT * FROM template WHERE name = $1", name)
		if err != nil {
			panic(err)
		}
		t, err := template.New("").Funcs(templateFuncs).Parse(tmpl.Content)
		if err != nil {
			panic(err)
		}
		rw.Header().Set("Content-Type", "text/html")
		err = t.Execute(rw, data)
		if err != nil {
			panic(err)
		}
	}

	http.HandleFunc("GET /login", func(rw http.ResponseWriter, req *http.Request) {
		runTemplate("login", rw, nil)
	})

	http.HandleFunc("POST /login", func(rw http.ResponseWriter, req *http.Request) {
		username := req.FormValue("username")
		password := req.FormValue("password")

		var u User
		err := w.db.Get(&u, `SELECT * FROM "user" WHERE "username" = $1`, username)
		if err != nil {
			http.Error(rw, "Invalid username or password", http.StatusUnauthorized)
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)) != nil {
			http.Error(rw, "Invalid username or password", http.StatusUnauthorized)
			return
		}
		id := make([]byte, 32)
		rand.Read(id)
		s := Session{
			ID:     string(id),
			UserID: u.ID,
		}
		w.db.Exec("INSERT INTO session (id, user_id) VALUES ($1, $2)", s.ID, s.UserID)
		http.SetCookie(rw, &http.Cookie{
			Name:   "session",
			Value:  string(id),
			MaxAge: 86400,
		})
	})

	getSession := func(req *http.Request) *Session {
		sidc, _ := req.Cookie("session")
		if sidc == nil {
			return nil
		}
		var s Session
		err := w.db.Get(&s, "SELECT * FROM session WHERE id = $1", sidc.Value)
		if err != nil {
			return nil
		}
		return &s
	}

	http.HandleFunc("/{page}", func(rw http.ResponseWriter, req *http.Request) {
		s := getSession(req)
		runTemplate("view", rw, struct {
			Page    string
			Session *Session
		}{
			req.PathValue("page"),
			s,
		})
	})

	http.HandleFunc("GET /{page}/edit", func(rw http.ResponseWriter, req *http.Request) {
		s := getSession(req)
		if s == nil {
			http.Redirect(rw, req, "/login", http.StatusFound)
			return
		}
		runTemplate("edit", rw, struct {
			Page    string
			Session *Session
		}{
			req.PathValue("page"),
			s,
		})
	})

	http.HandleFunc("POST /{page}/edit", func(rw http.ResponseWriter, req *http.Request) {
		s := getSession(req)
		if s == nil {
			http.Redirect(rw, req, "/login", http.StatusFound)
			return
		}
		content := req.FormValue("content")
		_, err := w.db.Exec("INSERT INTO page (slug, content) VALUES ($1, $2) ON CONFLICT (slug) DO UPDATE SET content = $2", req.PathValue("page"), content)
		if err != nil {
			panic(err)
		}
		http.Redirect(rw, req, "/"+req.PathValue("page"), http.StatusFound)
	})

	http.HandleFunc("GET /template/edit/{name}", func(rw http.ResponseWriter, req *http.Request) {
		s := getSession(req)
		if s == nil {
			http.Redirect(rw, req, "/login", http.StatusFound)
			return
		}
		var tmpl Template
		w.db.Get(&tmpl, "SELECT * FROM template WHERE name = $1", req.PathValue("name"))
		t, err := template.New("").Funcs(templateFuncs).Parse(simpleEdit)
		if err != nil {
			panic(err)
		}
		err = t.Execute(rw, struct {
			Page    string
			Content template.HTML
		}{
			req.PathValue("name"),
			template.HTML(tmpl.Content),
		})
		if err != nil {
			panic(err)
		}
	})

	http.HandleFunc("POST /template/edit/{name}", func(rw http.ResponseWriter, req *http.Request) {
		s := getSession(req)
		if s == nil {
			http.Redirect(rw, req, "/login", http.StatusFound)
			return
		}
		content := req.FormValue("content")
		_, err := w.db.Exec("INSERT INTO template (name, content) VALUES ($1, $2) ON CONFLICT (name) DO UPDATE SET content = $2", req.PathValue("name"), content)
		if err != nil {
			panic(err)
		}
		http.Redirect(rw, req, "/template/edit/"+req.PathValue("name"), http.StatusFound)
	})

	http.ListenAndServe(":8080", nil)
}

var simpleEdit = `
<!DOCTYPE html>
<html>
<head>
	<title>{{.Page}}</title>
</head>
<body>
	<form method="POST">
		<textarea name="content" style="width: 100%; height: 100%">{{.Content}}</textarea>
		<input type="submit" value="Save">
	</form>
</body>
</html>
`

func (w *wiki) WikiLink(href string, text string) string {
	err := w.db.Get(&Page{}, "SELECT 1 FROM page WHERE slug = $1", href)
	if err != nil {
		return `<a href="/` + href + `/edit" class="edit-link">` + text + `</a>`
	}
	return `<a href="/` + href + `">` + text + `</a>`
}
