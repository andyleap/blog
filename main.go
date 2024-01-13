package main

import (
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/andyleap/cajun"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jhunt/go-s3"
	"github.com/jmoiron/sqlx"
	"golang.org/x/crypto/bcrypt"
)

type Page struct {
	Slug        string `db:"slug" unique:"true"`
	Content     []byte `db:"content"`
	ContentType string `db:"content_type"`
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
	Name         string `db:"name" unique:"true"`
	Content      string `db:"content"`
	ContentType  string `db:"content_type"`
	TemplateType string `db:"template_type"`
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
		"renderCreole": func(creole []byte) (template.HTML, error) {
			out, err := c.Transform(string(creole))
			return template.HTML(out), err
		},
		"getRaw": func(path string) (*Page, error) {
			var page Page
			err := w.db.Get(&page, "SELECT * FROM page WHERE slug = $1", path)
			if err != nil {
				return nil, nil
			}
			return &page, nil
		},
		"getContentTypes": func() []string {
			var tmpls []Template
			err := w.db.Select(&tmpls, `SELECT "name" FROM "template"`)
			if err != nil {
				panic(err)
			}
			types := map[string]struct{}{}
			types["wiki"] = struct{}{}
			for _, tmpl := range tmpls {
				if strings.Contains(tmpl.Name, "-") {
					typ := strings.SplitN(tmpl.Name, "-", 2)[1]
					types[typ] = struct{}{}
				}
			}
			var out []string
			for typ := range types {
				out = append(out, typ)
			}
			sort.Strings(out)
			return out
		},
	}

	runTemplate := func(name string, rw http.ResponseWriter, data map[string]interface{}) {
		var tmpl Template
		err := w.db.Get(&tmpl, "SELECT * FROM template WHERE name = $1", name)
		if err != nil {
			panic(err)
		}
		rw.Header().Set("Content-Type", tmpl.ContentType)
		switch tmpl.TemplateType {
		case "raw":
			page := data["page"].(string)
			var p Page
			err := w.db.Get(&p, "SELECT * FROM page WHERE slug = $1", page)
			if err != nil {
				http.Error(rw, "Not found", http.StatusNotFound)
				return
			}
			rw.Write(p.Content)
		case "html":
			fallthrough
		default:
			t, err := template.New("").Funcs(templateFuncs).Parse(tmpl.Content)
			if err != nil {
				panic(err)
			}
			err = t.Execute(rw, data)
			if err != nil {
				panic(err)
			}
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
		sid := hex.EncodeToString(id)
		s := Session{
			ID:     sid,
			UserID: u.ID,
		}
		w.db.Exec("INSERT INTO session (id, user_id) VALUES ($1, $2)", s.ID, s.UserID)
		http.SetCookie(rw, &http.Cookie{
			Name:   "session",
			Value:  sid,
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
			Content      template.HTML
			ContentType  string
			TemplateType string
		}{
			template.HTML(tmpl.Content),
			tmpl.ContentType,
			tmpl.TemplateType,
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
		contentType := req.FormValue("content_type")
		templateType := req.FormValue("template_type")
		_, err := w.db.Exec("INSERT INTO template (name, content, content_type, template_type) VALUES ($1, $2, $3, $4) ON CONFLICT (name) DO UPDATE SET content = $2, content_type = $3, template_type = $4", req.PathValue("name"), content, contentType, templateType)
		if err != nil {
			panic(err)
		}
		http.Redirect(rw, req, "/template/edit/"+req.PathValue("name"), http.StatusFound)
	})

	http.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		s := getSession(req)
		page := strings.TrimPrefix(req.URL.Path, "/")
		parts := strings.Split(page, "/")
		edit := false
		if len(parts) > 0 {
			if parts[len(parts)-1] == "edit" {
				edit = true
				parts = parts[:len(parts)-1]
			}
		}
		page = strings.Join(parts, "/")
		if req.Method == "POST" {
			if s == nil {
				http.Redirect(rw, req, "/login", http.StatusFound)
				return
			}
			content := []byte(req.FormValue("content"))
			contentType := req.FormValue("content_type")
			f, _, err := req.FormFile("content")
			if err == nil {
				defer f.Close()
				buf, err := io.ReadAll(f)
				if err != nil {
					panic(err)
				}
				content = buf
			}
			_, err = w.db.Exec("INSERT INTO page (slug, content, content_type) VALUES ($1, $2, $3) ON CONFLICT (slug) DO UPDATE SET content = $2, content_type = $3", page, content, contentType)
			if err != nil {
				panic(err)
			}
			http.Redirect(rw, req, "/"+page, http.StatusFound)
			return
		}
		tmpl := "view"
		if edit {
			if s == nil {
				http.Redirect(rw, req, "/login", http.StatusFound)
				return
			}
			tmpl = "edit"
		}
		var contentType string
		w.db.Get(&contentType, "SELECT content_type FROM page WHERE slug = $1", page)
		if contentType == "" {
			contentType = "wiki"
		}
		if contentType != "wiki" {
			tmpl += "-" + contentType
		}
		runTemplate(tmpl, rw, map[string]interface{}{
			"Page":    page,
			"Session": s,
		})
	})

	http.ListenAndServe(":8080", nil)
}

var simpleEdit = `
<!DOCTYPE html>
<html>
<head>
</head>
<body>
	<form method="POST">
		<textarea name="content" style="width: 100%; height: 50vh;">{{.Content}}</textarea>
		<input type="text" name="content_type" value="{{.ContentType}}">
		<select name="template_type">
			<option value="html"{{if eq .TemplateType "html" ""}} selected{{end}}>Html</option>
			<option value="raw"{{if eq .TemplateType "raw"}} selected{{end}}>Raw</option>
		</select>
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
