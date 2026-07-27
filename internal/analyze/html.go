package analyze

import (
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

// FormInput describes a single form control.
type FormInput struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Hidden bool   `json:"hidden"`
}

// Form describes an HTML form discovered on a page.
type Form struct {
	Action   string      `json:"action"`
	Method   string      `json:"method"`
	Inputs   []FormInput `json:"inputs"`
	HasPass  bool        `json:"has_password"`
}

// Page holds structured data extracted from an HTML document.
type Page struct {
	Title   string
	Links   []string
	Scripts []string
	Forms   []Form
	Assets  []string // css, images, media
}

// ParsePage parses HTML body, resolving relative links against base.
func ParsePage(base string, body []byte) *Page {
	p := &Page{}
	baseURL, _ := url.Parse(base)

	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return p
	}

	resolve := func(ref string) string {
		ref = strings.TrimSpace(ref)
		if ref == "" || strings.HasPrefix(ref, "javascript:") || strings.HasPrefix(ref, "#") || strings.HasPrefix(ref, "mailto:") {
			return ""
		}
		u, err := url.Parse(ref)
		if err != nil {
			return ""
		}
		if baseURL != nil {
			return baseURL.ResolveReference(u).String()
		}
		return u.String()
	}

	var currentForm *Form
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "title":
				if n.FirstChild != nil && p.Title == "" {
					p.Title = strings.TrimSpace(n.FirstChild.Data)
				}
			case "a":
				if href := attr(n, "href"); href != "" {
					if r := resolve(href); r != "" {
						p.Links = append(p.Links, r)
					}
				}
			case "script":
				if src := attr(n, "src"); src != "" {
					if r := resolve(src); r != "" {
						p.Scripts = append(p.Scripts, r)
					}
				}
			case "link":
				if href := attr(n, "href"); href != "" {
					if r := resolve(href); r != "" {
						p.Assets = append(p.Assets, r)
					}
				}
			case "img", "source", "video", "audio":
				if src := attr(n, "src"); src != "" {
					if r := resolve(src); r != "" {
						p.Assets = append(p.Assets, r)
					}
				}
			case "form":
				f := Form{Action: resolve(attr(n, "action")), Method: strings.ToUpper(attr(n, "method"))}
				if f.Method == "" {
					f.Method = "GET"
				}
				if f.Action == "" {
					f.Action = base
				}
				currentForm = &f
			case "input", "textarea", "select":
				in := FormInput{
					Name:   attr(n, "name"),
					Type:   strings.ToLower(attr(n, "type")),
					Hidden: strings.EqualFold(attr(n, "type"), "hidden"),
				}
				if in.Type == "password" && currentForm != nil {
					currentForm.HasPass = true
				}
				if currentForm != nil {
					currentForm.Inputs = append(currentForm.Inputs, in)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
			if n.Type == html.ElementNode && n.Data == "form" && currentForm != nil && c.NextSibling == nil {
				p.Forms = append(p.Forms, *currentForm)
				currentForm = nil
			}
		}
	}
	walk(doc)

	p.Links = dedup(p.Links)
	p.Scripts = dedup(p.Scripts)
	p.Assets = dedup(p.Assets)
	return p
}

// Title extracts just the <title> text from an HTML body (cheap).
func Title(body []byte) string {
	lower := strings.ToLower(string(body))
	i := strings.Index(lower, "<title")
	if i < 0 {
		return ""
	}
	j := strings.IndexByte(lower[i:], '>')
	if j < 0 {
		return ""
	}
	start := i + j + 1
	k := strings.Index(lower[start:], "</title>")
	if k < 0 {
		return ""
	}
	return strings.TrimSpace(string(body)[start : start+k])
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}
