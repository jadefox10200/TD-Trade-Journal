package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/securecookie"
	"github.com/joncooperworks/go-tdameritrade"
	"golang.org/x/oauth2"
)

type DbDao struct {
	db *sql.DB
}

var db DbDao

func (d *DbDao) Init(connstr string) error {

	db, err := sql.Open("mysql", connstr)
	if err != nil {
		return err
	}
	err = db.Ping()
	if err != nil {
		return err
	}
	d.db = db
	return nil
}

var port = ":8080"

var hashKey = []byte("")
var blockKey = []byte("")

func main() {

	dbString := "root:10200mille@/TradeJournal"
	err := db.Init(dbString)
	if err != nil {
		log.Fatal("Failed to create db connection:", err.Error())
	}

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
	http.HandleFunc("/saveTransactions", handlers.SaveTransactions)

	http.HandleFunc("/tpl/", handlers.Templates)

	//HANDLE ALL FILES IN THE assets FOLDER THAT THE SITE WILL NEED AND THAT A USER CAN ACCESS.
	http.Handle("/assets/", http.StripPrefix("/assets", http.FileServer(http.Dir("assets/"))))

	//SERVE THE PUBLIC FOLDER
	http.Handle("/public/", http.StripPrefix("/public", http.FileServer(http.Dir("public/"))))

	http.HandleFunc("/", handlers.Index)

	log.Fatal(http.ListenAndServe(port, nil))
}

type HTTPHeaderStore struct {
	Cookie *securecookie.SecureCookie
}

const TimeFormat = "Mon, 02 Jan 2006 15:04:05 GMT"

func (s *HTTPHeaderStore) StoreToken(token *oauth2.Token, w http.ResponseWriter, req *http.Request) error {

	fmt.Println("MyAccess: ", token.AccessToken)
	fmt.Println("MyRefresh: ", token.RefreshToken)
	fmt.Println("MyExpiry: ", token.Expiry)

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
		// MaxAge: 1800,
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
		Expiry:       accessToken.Expires,
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
		//we assume that if there is an error, we should log back in:
		redirectURL := fmt.Sprintf("http://localhost%s/authenticate", port)
		http.Redirect(w, req, redirectURL, http.StatusTemporaryRedirect)
		return
	}

	start, okStart := req.URL.Query()["start"]
	end, okEnd := req.URL.Query()["end"]
	if !okStart || !okEnd || start[0] == "" || end[0] == "" {
		http.Error(w, "Your date provided isn't valid. Must provide start and end date", 400)
		return
	}

	opts := &tdameritrade.TransactionHistoryOptions{
		Type:      "TRADE",
		StartDate: start[0],
		EndDate:   end[0],
	}

	acctID := os.Getenv("TDAMERITRADE_ACCT_ID")

	transactions, _, err := client.TransactionHistory.GetTransactions(ctx, acctID, opts)
	if err != nil {
		http.Error(w,
			fmt.Sprintf("GetTransactions produced the following error: %s.\n", err.Error()),
			400)
	}
	err = json.NewEncoder(w).Encode(transactions)
	if err != nil {
		http.Error(w,
			fmt.Sprintf("GetTransactions produced the following error during encoding: %s.\n", err.Error()),
			500)
	}

	return

}

func (h *TDHandlers) SaveTransactions(w http.ResponseWriter, req *http.Request) {

	ctx := context.Background()
	client, err := h.authenticator.AuthenticatedClient(ctx, req)
	if err != nil {
		//TODO: THIS DOESN'T WORK AND NEEDS TO BE FIXED: !!!!
		//we assume that if there is an error, we should log back in:
		redirectURL := fmt.Sprintf("http://localhost%s/authenticate", port)
		http.Redirect(w, req, redirectURL, http.StatusTemporaryRedirect)
		return
	}

	start, okStart := req.URL.Query()["start"]
	end, okEnd := req.URL.Query()["end"]
	if !okStart || !okEnd || start[0] == "" || end[0] == "" {
		http.Error(w, "Your date provided isn't valid. Must provide start and end date", 400)
		return
	}

	opts := &tdameritrade.TransactionHistoryOptions{
		Type:      "TRADE",
		StartDate: start[0],
		EndDate:   end[0],
	}

	acctID := os.Getenv("TDAMERITRADE_ACCT_ID")

	transactions, _, err := client.TransactionHistory.GetTransactions(ctx, acctID, opts)
	if err != nil {
		http.Error(w,
			fmt.Sprintf("GetTransactions produced the following error: %s.\n", err.Error()),
			400)
	}

	err = db.insertTransactions(transactions)
	if err != nil {
		http.Error(w,
			fmt.Sprintf("Failed to insert transactions: %s.\n", err.Error()),
			500)
	}

	err = json.NewEncoder(w).Encode(transactions)
	if err != nil {
		http.Error(w,
			fmt.Sprintf("Transactions were saved, but not marshalled on return: %s.\n", err.Error()),
			500)
	}

	return

}

func (db *DbDao) insertTransactions(t *tdameritrade.Transactions) error {

	sqlStr := "INSERT INTO tradeTransactions( orderId,Type,ClearingReferenceNumber,SubAccount,SettlementDate,SMA,RequirementReallocationAmount,DayTradeBuyingPowerEffect,NetAmount,TransactionDate,OrderDate,TransactionSubType,TransactionID,CashBalanceEffectFlag,Description,ACHStatus,AccruedInterest,Fees,AccountID,Amount,Price,Cost,ParentOrderKey,ParentChildIndicator,Instruction,PositionEffect,Symbol,UnderlyingSymbol,OptionExpirationDate,OptionStrikePrice,PutCall,CUSIP,InstrumentDescription,AssetType,BondMaturityDate,BondInterestRate) VALUES "

	vals := []interface{}{}
	var counter int
	for _, row := range *t {
		var id int64
		err := db.db.QueryRow("select TransactionId from tradeTransactions where TransactionId = ?", row.TransactionID).Scan(id)
		//if anything is returned, skip this row as we got a result.
		if err != sql.ErrNoRows {
			continue
		} else if err != nil {
			return err
		}

		var fees float64
		fees += row.Fees.AdditionalFee
		fees += row.Fees.CdscFee
		fees += row.Fees.Commission
		fees += row.Fees.OptRegFee
		fees += row.Fees.OtherCharges
		fees += row.Fees.RFee
		fees += row.Fees.RegFee
		fees += row.Fees.SecFee
		//36 columns
		sqlStr += "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?),"
		vals = append(vals, row.OrderID, row.Type, row.ClearingReferenceNumber, row.SubAccount, row.SettlementDate, row.SMA, row.RequirementReallocationAmount, row.DayTradeBuyingPowerEffect, row.NetAmount, row.TransactionDate, row.OrderDate, row.TransactionSubType, row.TransactionID, row.CashBalanceEffectFlag, row.Description, row.ACHStatus, row.AccruedInterest, fees, row.TransactionItem.AccountID, row.TransactionItem.Amount, row.TransactionItem.Price, row.TransactionItem.Cost, row.TransactionItem.ParentOrderKey, row.TransactionItem.ParentChildIndicator, row.TransactionItem.Instruction, row.TransactionItem.PositionEffect, row.TransactionItem.Instrument.Symbol, row.TransactionItem.Instrument.UnderlyingSymbol, row.TransactionItem.Instrument.OptionExpirationDate, row.TransactionItem.Instrument.OptionStrikePrice, row.TransactionItem.Instrument.PutCall, row.TransactionItem.Instrument.CUSIP, row.TransactionItem.Instrument.Description, row.TransactionItem.Instrument.AssetType, row.TransactionItem.Instrument.BondMaturityDate, row.TransactionItem.Instrument.BondInterestRate)

		counter++
	}

	if counter == 0 {
		return fmt.Errorf("There were no new rows found to upload")
	}

	//trim the last,
	sqlStr = strings.TrimSuffix(sqlStr, ",")

	//prepare the statement
	stmt, err := db.db.Prepare(sqlStr)
	if err != nil {
		return err
	}

	defer stmt.Close()

	//format all vals at once
	res, err := stmt.Exec(vals...)
	if err != nil {
		return err
	}

	num, _ := res.RowsAffected()

	fmt.Println("Result of insert:", num)
	fmt.Println("Counter should match rows:", counter)

	return nil

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
	// _, err := h.authenticator.Store.GetToken(req)
	// if err != nil {
	// 	fmt.Println("Error: ", err.Error())
	// 	//reroute to login:
	// 	redirectURL := fmt.Sprintf("http://localhost%s/authenticate", port)
	// 	http.Redirect(w, req, redirectURL, http.StatusTemporaryRedirect)
	// 	return
	// }

	renderTemplate(w, req, "home", nil)

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

type TransactionRow struct {
	OrderID                       string  `json:"orderId"`
	Type                          string  `json:"type"`
	ClearingReferenceNumber       string  `json:"clearingReferenceNumber"`
	SubAccount                    string  `json:"subAccount"`
	SettlementDate                string  `json:"settlementDate"`
	SMA                           float64 `json:"sma"`
	RequirementReallocationAmount float64 `json:"requirementReallocationAmount"`
	DayTradeBuyingPowerEffect     float64 `json:"dayTradeBuyingPowerEffect"`
	NetAmount                     float64 `json:"netAmount"`
	TransactionDate               string  `json:"transactionDate"`
	OrderDate                     string  `json:"orderDate"`
	TransactionSubType            string  `json:"transactionSubType"`
	TransactionID                 int64   `json:"transactionId"`
	CashBalanceEffectFlag         bool    `json:"cashBalanceEffectFlag"`
	Description                   string  `json:"description"`
	ACHStatus                     string  `json:"achStatus"`
	AccruedInterest               float64 `json:"accruedInterest"`
	Fees                          float64 `json:"fees"`
	AccountID                     int32   `json:"accountId"`
	Amount                        float64 `json:"amount"`
	Price                         float64 `json:"price"`
	Cost                          float64 `json:"cost"`
	ParentOrderKey                int32   `json:"parentOrderKey"`
	ParentChildIndicator          string  `json:"parentChildIndicator"`
	Instruction                   string  `json:"instruction"`
	PositionEffect                string  `json:"positionEffect"`
	Symbol                        string  `json:"symbol"`
	UnderlyingSymbol              string  `json:"underlyingSymbol"`
	OptionExpirationDate          string  `json:"optionExpirationDate"`
	OptionStrikePrice             float64 `json:"optionStrikePrice"`
	PutCall                       string  `json:"putCall"`
	CUSIP                         string  `json:"cusip"`
	InstrumentDescription         string  `json:"instrumentDescription"`
	AssetType                     string  `json:"assetType"`
	BondMaturityDate              string  `json:"bondMaturityDate"`
	BondInterestRate              float64 `json:"bondInterestRate"`
}

// func ConstructTransactionRows(tdameritrade.Transactions) float64 {
// 	var sum float64
// 	for _, v := range t {
// 		sum += v
// 	}
//
// 	var t = &TransactionRow{}
//
// 	return t
// }
//
// func (h *TDHandlers) LoadTradeData(w http.ResponseWriter, req *http.Request) {
//
// 	ctx := context.Background()
// 	client, err := h.authenticator.AuthenticatedClient(ctx, req)
// 	if err != nil {
// 		w.Write([]byte(err.Error()))
// 		w.WriteHeader(http.StatusInternalServerError)
// 		return
// 	}
//
// 	opts := &tdameritrade.TransactionHistoryOptions{
// 		StartDate: "2021-02-01",
// 		EndDate:   "2021-02-03",
// 	}
//
// 	acctID := os.Getenv("TDAMERITRADE_ACCT_ID")
//
// 	transactions, resp, err := client.TransactionHistory.GetTransactions(ctx, acctID, opts)
//
// 	uploadTransactionsSQL(transactions)
//
// 	body, err := json.Marshal(transactions)
// 	if err != nil {
// 		w.Write([]byte(err.Error()))
// 		w.WriteHeader(http.StatusInternalServerError)
// 		return
// 	}
//
// 	w.Write(body)
// 	w.WriteHeader(resp.StatusCode)
//
// }

//change this so it is simply a generic template loader:
func (h *TDHandlers) Templates(w http.ResponseWriter, r *http.Request) {

	name := strings.TrimLeft(r.URL.Path, "/tpl/")

	var tokenState bool
	// _, err := h.authenticator.Store.GetToken(r)
	// if err == nil {
	// 	tokenState = true
	// }

	ctx := context.Background()
	_, err := h.authenticator.AuthenticatedClient(ctx, r)
	if err == nil {
		tokenState = true
	}

	if name == "dayView" {
		var dateTime = time.Now().Format("Mon, 2 Jan 2006")
		var dateRaw = time.Now().Format("2006-01-02")

		dateInput := r.URL.Query().Get("date")

		//if we got a date from the user so need to parse it and serve that date:
		if dateInput != "" {
			parsedDate, err := time.Parse("2006-01-02", dateInput)
			dateTime = parsedDate.Format("Mon, 2 Jan 2006")
			dateRaw = parsedDate.Format("2006-01-02")
			if err != nil {
				http.Error(w,
					fmt.Sprintf("Couldn't parse provided date. Must be format YYYY-MM-MM: %s", err.Error()),
					500,
				)
				return
			}
		}

		data := struct {
			LoggedIn     bool
			Date         string
			DateRaw      string
			TradeCount   int
			SharesTraded int
			ClosedGross  float64
			TotalFees    float64
			FinalPL      float64
			Loaded       bool
		}{tokenState, dateTime, dateRaw, 0, 0, 0.0, 0.0, 0.0, false}

		renderTemplate(w, r, name, data)
		return

	}

	data := struct {
		LoggedIn bool
	}{tokenState}

	renderTemplate(w, r, name, data)

	return
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
		PageName: template.HTML(`<link rel="stylesheet" type="text/css" href="/public/css/` + name + `.css">`),
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

// type TransactionList tdameritrade.Transactions
//
// func (t TransactionList) Len() int {
// 	return len(t)
// }
//
// func (t TransactionList) Less(i, j int) bool {
// 	return t[i].TransactionDate > t[j].TransactionDate
// }
//
// func (t TransactionList) Swap(i, j int) {
// 	t[i], t[j] = t[j], t[i]
// }
