package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/joncooperworks/go-tdameritrade"
	"golang.org/x/oauth2"
)

type HTTPHeaderStore struct {
	Cookie *securecookie.SecureCookie
}

func (s *HTTPHeaderStore) StoreToken(token *oauth2.Token, w http.ResponseWriter, req *http.Request) error {

	err := s.SetEncodedCookie(w, "accessToken", token.AccessToken, token.Expiry)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return err
	}

	err = s.SetEncodedCookie(w, "refreshToken", token.RefreshToken, token.Expiry)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return err
	}

	return nil
}

func (s *HTTPHeaderStore) SetEncodedCookie(w http.ResponseWriter, cookieName string, value string, expiry time.Time) error {

	encoded, err := s.Cookie.Encode(cookieName, value)
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Name:    cookieName,
		Value:   encoded,
		Expires: expiry,
	}
	http.SetCookie(w, cookie)

	return nil
}

func (s HTTPHeaderStore) GetToken(req *http.Request) (*oauth2.Token, error) {
	// DO NOT DO THIS IN A PRODUCTION ENVIRONMENT!
	// This is just an example.
	// Used signed cookies like those provided by https://github.com/gorilla/securecookie

	refreshToken, err := req.Cookie("refreshToken")
	if err != nil {
		return nil, err
	}

	err = s.Cookie.Decode("refreshToken", refreshToken.Value, &refreshToken.Value)
	if err != nil {
		return nil, err
	}

	accessToken, err := req.Cookie("accessToken")
	if err != nil {
		return nil, err
	}

	err = s.Cookie.Decode("accessToken", accessToken.Value, &accessToken.Value)
	if err != nil {
		return nil, err
	}

	return &oauth2.Token{
		AccessToken:  accessToken.Value,
		RefreshToken: refreshToken.Value,
		Expiry:       refreshToken.Expires,
	}, nil
}

func (s HTTPHeaderStore) StoreState(state string, w http.ResponseWriter, req *http.Request) error {
	// DO NOT DO THIS IN A PRODUCTION ENVIRONMENT!
	// This is just an example.
	// Used signed cookies like those provided by https://github.com/gorilla/securecookie
	http.SetCookie(
		w,
		&http.Cookie{
			Name:  "state",
			Value: state,
		},
	)
	return nil
}

func (s HTTPHeaderStore) GetState(req *http.Request) (string, error) {
	// DO NOT DO THIS IN A PRODUCTION ENVIRONMENT!
	// This is just an example.
	// Used signed cookies like those provided by https://github.com/gorilla/securecookie
	cookie, err := req.Cookie("state")
	if err != nil {
		return "", err
	}

	return cookie.Value, nil
}

type TDHandlers struct {
	authenticator *tdameritrade.Authenticator
}

func (h *TDHandlers) Authenticate(w http.ResponseWriter, req *http.Request) {
	redirectURL, err := h.authenticator.StartOAuth2Flow(w, req)
	if err != nil {
		w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, redirectURL, http.StatusTemporaryRedirect)
}

func (h *TDHandlers) Callback(w http.ResponseWriter, req *http.Request) {
	ctx := context.Background()
	_, err := h.authenticator.FinishOAuth2Flow(ctx, w, req)
	if err != nil {
		w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, req, "/", http.StatusTemporaryRedirect)
}

func (h *TDHandlers) TransactionHistory(w http.ResponseWriter, req *http.Request) {

	ctx := context.Background()
	client, err := h.authenticator.AuthenticatedClient(ctx, req)
	if err != nil {
		w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	opts := &tdameritrade.TransactionHistoryOptions{
		StartDate: "2021-02-01",
		EndDate:   "2021-02-03",
	}

	acctID := os.Getenv("TDAMERITRADE_ACCT_ID")

	transactions, resp, err := client.TransactionHistory.GetTransactions(ctx, acctID, opts)

	body, err := json.Marshal(transactions)
	if err != nil {
		w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(body)
	w.WriteHeader(resp.StatusCode)

}

func (h *TDHandlers) Quote(w http.ResponseWriter, req *http.Request) {
	ctx := context.Background()
	client, err := h.authenticator.AuthenticatedClient(ctx, req)
	if err != nil {
		w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	ticker, ok := req.URL.Query()["ticker"]
	if !ok || len(ticker) == 0 {
		w.Write([]byte("ticker is required"))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	quote, resp, err := client.Quotes.GetQuotes(ctx, ticker[0])
	if err != nil {
		w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	body, err := json.Marshal(quote)
	if err != nil {
		w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(body)
	w.WriteHeader(resp.StatusCode)

}

func (h *TDHandlers) Index(w http.ResponseWriter, req *http.Request) {

	//make sure we are logged in before going to index.html
	_, err := h.authenticator.Store.GetToken(req)
	if err != nil {
		fmt.Println("Error: ", err.Error())
		//reroute to login:
		redirectURL := fmt.Sprintf("http://localhost%s/authenticate", port)
		http.Redirect(w, req, redirectURL, http.StatusTemporaryRedirect)
		return
	}

	renderTemplate(w, req, "monthView", nil)

	// http.ServeFile(w, req, "index.html")

}

func (h *TDHandlers) Movers(w http.ResponseWriter, req *http.Request) {
	ctx := context.Background()
	client, err := h.authenticator.AuthenticatedClient(ctx, req)
	if err != nil {
		w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	ph, resp, err := client.Mover.Mover(ctx, "$COMPX", nil)
	if err != nil {
		log.Fatal(err)
	}

	body, err := json.Marshal(ph)
	if err != nil {
		w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(body)
	w.WriteHeader(resp.StatusCode)

}

var port = ":8080"

var hashKey = []byte("")
var blockKey = []byte("")

func main() {

	hashKey = securecookie.GenerateRandomKey(32)
	blockKey = securecookie.GenerateRandomKey(32)

	ck := securecookie.New(hashKey, blockKey)

	clientID := os.Getenv("TDAMERITRADE_CLIENT_ID")
	if clientID == "" {
		log.Fatal("Unauthorized: No client ID present")
	}

	authenticator := tdameritrade.NewAuthenticator(
		&HTTPHeaderStore{
			Cookie: ck,
		},
		oauth2.Config{
			ClientID: clientID,
			Endpoint: oauth2.Endpoint{
				TokenURL: "https://api.tdameritrade.com/v1/oauth2/token",
				AuthURL:  "https://auth.tdameritrade.com/auth",
			},
			RedirectURL: "http://localhost:8080/callback",
		},
	)
	handlers := &TDHandlers{authenticator: authenticator}
	http.HandleFunc("/authenticate", handlers.Authenticate)
	http.HandleFunc("/callback", handlers.Callback)
	http.HandleFunc("/quote", handlers.Quote)
	http.HandleFunc("/movers", handlers.Movers)
	http.HandleFunc("/transactionHistory", handlers.TransactionHistory)

	//HANDLE ALL FILES IN THE assets FOLDER THAT THE SITE WILL NEED AND THAT A USER CAN ACCESS.
	http.Handle("/assets/", http.StripPrefix("/assets", http.FileServer(http.Dir("assets/"))))

	//SERVE THE PUBLIC FOLDER
	http.Handle("/public/", http.StripPrefix("/public", http.FileServer(http.Dir("public/"))))

	http.HandleFunc("/", handlers.Index)

	log.Fatal(http.ListenAndServe(port, nil))
}

func renderTemplate(w http.ResponseWriter, r *http.Request, name string, data interface{}) {
	// parse templates
	tpl := template.New("")
	tpl, err := tpl.ParseGlob("templates/*.gohtml")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// execute page
	var bufBody, bufHeader, bufFooter bytes.Buffer
	err = tpl.ExecuteTemplate(&bufHeader, "header", data)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	err = tpl.ExecuteTemplate(&bufBody, name, data)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	err = tpl.ExecuteTemplate(&bufFooter, "footer", data)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// execute layout
	type Model struct {
		Header   template.HTML
		Body     template.HTML
		LoggedIn bool
		PageName template.HTML
		Footer   template.HTML
	}
	model := Model{
		PageName: template.HTML(`<link rel="stylesheet" type="text/css" href="/assets/css/pagecss/` + name + `.css">`),
		Header:   template.HTML(bufHeader.String()),
		Body:     template.HTML(bufBody.String()),
		Footer:   template.HTML(bufBody.String()),
	}
	// log.Println("Render template COOKIE:", r.Cookies())
	// testCookie, _ := r.Cookie("session")
	// log.Println("Render template COOKIE:", testCookie)
	// if cookie, err := r.Cookie("session"); err == nil {
	// 	model.LoggedIn = cookie.Value == "true"
	// }
	err = tpl.ExecuteTemplate(w, "index", model)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	return

}
