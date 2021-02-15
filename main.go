package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/securecookie"
	"github.com/jadefox10200/go-tdameritrade"
	"golang.org/x/oauth2"
)

//TODO: IMPROVE LOG IN COOKIE STATE
//TODO: FIX LOGGED IN STATUS IN THE RENDERTEMPLTE() FUNCTION.
//TODO: FIX MONTH VIEW SO WHEN CLICKING BACK, IT TAKES YOU TO THE MONTH YOU WERE LAST LOOKING AT.

//TODO: MAKE A TRADE VIEW PAGE INCLUDING A CHART SHOWING ENTRY AND EXIT
//TODO: Fix Trade TABLE VIEW SO THAT IT PULLS FROM THE TRADE TABLE AND MAKE EACH ROW CLICKABL
//TODO: BUILD FEATURE FOR ADDING NOTES TO TRADES AND TO DAYS.

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
	http.HandleFunc("/getOrders", handlers.GetOrders)
	http.HandleFunc("/saveOrders", handlers.SaveOrders)
	http.HandleFunc("/saveTrades", handlers.SaveTrades)
	http.HandleFunc("/getTrades", handlers.GetTrades)
	http.HandleFunc("/getTradesForDayView", GetTradesForDayView)

	http.HandleFunc("/getEventsByQuery/", GetEventsByQuery)

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
		http.Error(w, "Failed to authenticate", 401)
		return
	}

	http.Redirect(w, req, redirectURL, http.StatusTemporaryRedirect)
}

func (h *TDHandlers) Callback(w http.ResponseWriter, req *http.Request) {
	ctx := context.Background()
	_, err := h.authenticator.FinishOAuth2Flow(ctx, w, req)
	if err != nil {
		http.Error(w, "Failed to authenticate", 401)
		return
	}

	http.Redirect(w, req, "/", http.StatusTemporaryRedirect)
}

func (h *TDHandlers) TransactionHistory(w http.ResponseWriter, req *http.Request) {

	ctx := context.Background()
	client, err := h.authenticator.AuthenticatedClient(ctx, req)
	if err != nil {
		//we assume that if there is an error, we should log back in:
		http.Error(w, "Failed to authenticate", 401)
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
		http.Error(w, "Failed to authenticate", 401)
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

	num, err := db.insertTransactions(transactions)
	if err != nil {
		http.Error(w,
			fmt.Sprintf("Failed to insert transactions: %s.\n", err.Error()),
			500)
		return
	}

	io.WriteString(w, fmt.Sprintf("Inserted %v transactions", num))

	// err = json.NewEncoder(w).Encode(transactions)
	// if err != nil {
	// 	http.Error(w,
	// 		fmt.Sprintf("Transactions were saved, but not marshalled on return: %s.\n", err.Error()),
	// 		500)
	// 	return
	// }

	return

}

func (db *DbDao) insertTransactions(t *tdameritrade.Transactions) (int64, error) {

	sqlStr := "INSERT IGNORE INTO tradeTransactions( orderId, Type ,ClearingReferenceNumber,SubAccount,SettlementDate,SMA,RequirementReallocationAmount,DayTradeBuyingPowerEffect,NetAmount,TransactionDate,OrderDate,TransactionSubType,TransactionID,CashBalanceEffectFlag,Description,ACHStatus,AccruedInterest,Fees,AccountID,Amount,Price,Cost,ParentOrderKey,ParentChildIndicator,Instruction,PositionEffect,Symbol,UnderlyingSymbol,OptionExpirationDate,OptionStrikePrice,PutCall,CUSIP,InstrumentDescription,AssetType,BondMaturityDate,BondInterestRate) VALUES "

	vals := []interface{}{}
	for _, row := range *t {

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
		vals = append(vals, row.OrderID, "TRADE", row.ClearingReferenceNumber, row.SubAccount, row.SettlementDate, row.SMA, row.RequirementReallocationAmount, row.DayTradeBuyingPowerEffect, row.NetAmount, row.TransactionDate, row.OrderDate, row.TransactionSubType, row.TransactionID, row.CashBalanceEffectFlag, row.Description, row.ACHStatus, row.AccruedInterest, fees, row.TransactionItem.AccountID, row.TransactionItem.Amount, row.TransactionItem.Price, row.TransactionItem.Cost, row.TransactionItem.ParentOrderKey, row.TransactionItem.ParentChildIndicator, row.TransactionItem.Instruction, row.TransactionItem.PositionEffect, row.TransactionItem.Instrument.Symbol, row.TransactionItem.Instrument.UnderlyingSymbol, row.TransactionItem.Instrument.OptionExpirationDate, row.TransactionItem.Instrument.OptionStrikePrice, row.TransactionItem.Instrument.PutCall, row.TransactionItem.Instrument.CUSIP, row.TransactionItem.Instrument.Description, row.TransactionItem.Instrument.AssetType, row.TransactionItem.Instrument.BondMaturityDate, row.TransactionItem.Instrument.BondInterestRate)

	}

	//trim the last,
	sqlStr = strings.TrimSuffix(sqlStr, ",")

	//prepare the statement
	stmt, err := db.db.Prepare(sqlStr)
	if err != nil {
		return 0, err
	}

	defer stmt.Close()

	//format all vals at once
	res, err := stmt.Exec(vals...)
	if err != nil {
		return 0, err
	}

	num, _ := res.RowsAffected()

	fmt.Println("Result of insert:", num)

	return num, nil

}

type InstrumentEquity struct {
	AssetType string
	Cusip     string
	Symbol    string
}

func (db *DbDao) insertOrders(o *tdameritrade.Orders) error {
	sqlStr := "INSERT IGNORE INTO orderHistory(orderId, symbol, positionEffect, instruction, quantity, price, orderDate, positionStatus) VALUES "

	vals := []interface{}{}
	for _, row := range *o {
		//8 columns
		sqlStr += "(?, ?, ?, ?, ?, ?, ?, ?),"
		id := row.OrderID
		iData, err := row.OrderLegCollection[0].Instrument.MarshalJSON()
		if err != nil {
			return fmt.Errorf("Couldn't marshalJSON(): %s", err.Error())
		}

		ie := InstrumentEquity{}
		err = json.Unmarshal(iData, &ie)
		if ie.Symbol == "" || err != nil {
			return fmt.Errorf("Didn't find the symbol field")
		}

		positionEffect := row.OrderLegCollection[0].PositionEffect
		instruction := row.OrderLegCollection[0].Instruction
		quantity := row.OrderActivityCollection[0].ExecutionLegs[0].Quantity
		price := row.OrderActivityCollection[0].ExecutionLegs[0].Price
		orderDate := row.OrderActivityCollection[0].ExecutionLegs[0].Time

		vals = append(vals, id, ie.Symbol, positionEffect, instruction, quantity, price, orderDate, "OPEN")

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

	return nil
}

func (h *TDHandlers) SaveOrders(w http.ResponseWriter, req *http.Request) {

	ctx := context.Background()
	client, err := h.authenticator.AuthenticatedClient(ctx, req)
	if err != nil {
		//we assume that if there is an error, we should log back in:
		http.Error(w, "Failed to authenticate", 401)
		return
	}

	start, okStart := req.URL.Query()["start"]
	end, okEnd := req.URL.Query()["end"]
	if !okStart || !okEnd || start[0] == "" || end[0] == "" {
		http.Error(w, "Your date provided isn't valid. Must provide start and end date", 400)
		return
	}

	acctId := os.Getenv("TDAMERITRADE_ACCT_ID")

	opts := &tdameritrade.OrderParams{
		AccountId: acctId,
		From:      start[0],
		To:        end[0],
		Status:    "FILLED",
	}

	orders, _, err := client.Account.GetOrdersByQuery(ctx, opts)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	err = db.insertOrders(orders)
	if err != nil {
		http.Error(w,
			fmt.Sprintf("Failed to insert transactions: %s.\n", err.Error()),
			500)
		return
	}

	err = json.NewEncoder(w).Encode(orders)
	if err != nil {
		http.Error(w,
			fmt.Sprintf("GerOrders produced the following error during encoding: %s.\n", err.Error()),
			500)
		return
	}

	return
}

func (h *TDHandlers) GetOrders(w http.ResponseWriter, req *http.Request) {
	ctx := context.Background()
	client, err := h.authenticator.AuthenticatedClient(ctx, req)
	if err != nil {
		//we assume that if there is an error, we should log back in:
		http.Error(w, "Failed to authenticate", 401)
		return
	}

	start, okStart := req.URL.Query()["start"]
	end, okEnd := req.URL.Query()["end"]
	if !okStart || !okEnd || start[0] == "" || end[0] == "" {
		http.Error(w, "Your date provided isn't valid. Must provide start and end date", 400)
		return
	}

	acctId := os.Getenv("TDAMERITRADE_ACCT_ID")

	opts := &tdameritrade.OrderParams{
		AccountId: acctId,
		From:      start[0],
		To:        end[0],
		Status:    "FILLED",
	}

	orders, _, err := client.Account.GetOrdersByQuery(ctx, opts)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	err = json.NewEncoder(w).Encode(orders)
	if err != nil {
		http.Error(w,
			fmt.Sprintf("GetOrders produced the following error during encoding: %s.\n", err.Error()),
			500)
		return
	}

	return

}

type Trade struct {
	ID            int
	Symbol        string
	ProfitLoss    float64
	Quantity      int
	EntryPrice    float64
	ExitPrice     float64
	OpenDate      string
	CloseDate     string
	TradeType     string
	AvgEntryPrice float64
	AvgExitPrice  float64
	PercentGain   float64
	Executions    int
	TradeStatus   string
	OrderIdSlice  []string
}

type TradeOrder struct {
	OrderId        string
	Symbol         string  `sql:"symbol"`
	Instruction    string  `sql:"instruction"`
	Quantity       float64 `sql:"amount"`
	Price          float64 `sql:"price"`
	OrderDate      string  `sql:"orderDate"`
	PositionStatus string  `sql:"positionStatus"`
}

func (h *TDHandlers) GetTrades(w http.ResponseWriter, req *http.Request) {

	tradeRows, err := CompileTrades(false)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	err = json.NewEncoder(w).Encode(tradeRows)
	if err != nil {
		http.Error(w,
			fmt.Sprintf("GetTrades produced the following error during encoding: %s.\n", err.Error()),
			500)
		return
	}

	return

}

func (h *TDHandlers) SaveTrades(w http.ResponseWriter, req *http.Request) {

	tx, err := db.db.Begin()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to begin tx: %s", err.Error()), 500)
		return
	}

	tradeRows, err := CompileTrades(true)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	insertStr := "INSERT INTO tradeHistory(symbol, profitLoss, quantity, entryPrice, exitPrice, openDate, closeDate, tradeType, avgEntryPrice, avgExitPrice, percentGain, executions) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
	updateStr := "UPDATE tradeTransactions SET tradeStatus = 'CLOSED' where orderId = ?"
	var affected int64
	for k, v := range tradeRows {
		if v.TradeStatus != "CLOSED" {
			continue
		}

		result, err := tx.Exec(insertStr, v.Symbol, v.ProfitLoss, v.Quantity, v.EntryPrice, v.ExitPrice, v.OpenDate, v.CloseDate, v.TradeType, v.AvgEntryPrice, v.AvgExitPrice, v.PercentGain, v.Executions)
		if err != nil {
			tx.Rollback()
			http.Error(w, fmt.Sprintf("Failed to insert a row with symbol: %s|%s|line: %v", v.Symbol, v.OpenDate, k), 500)
			return
		}
		i, err := result.RowsAffected()
		if err != nil {
			tx.Rollback()
			http.Error(w, "Failed to check rowsaffected somehow", 500)
			return
		}
		affected += i
		if len(v.OrderIdSlice) < 1 {
			tx.Rollback()
			http.Error(w, fmt.Sprintf("Something is wrong. OrderIdSlice is empty for %s|%s", v.Symbol, v.OpenDate), 500)
			return
		}
		for _, j := range v.OrderIdSlice {

			result, err := tx.Exec(updateStr, j)
			if err != nil {
				tx.Rollback()
				http.Error(w, fmt.Sprintf("Failed to update a row with id: %s|%s", j, err.Error()), 500)
				return
			}
			num, err := result.RowsAffected()
			if err != nil || num != 1 {
				tx.Rollback()
				http.Error(w, fmt.Sprintf("Something went wrong with the result id: %s", j), 500)
			}
		}
	}

	err = tx.Commit()
	if err != nil {
		fmt.Println("Failed to execution tx commit on save trades...")
		http.Error(w, fmt.Sprintf("Failed to commit on save trades: %s", err.Error()), 500)
		tx.Rollback()
		return
	}

	io.WriteString(w, fmt.Sprintf("Saved %v trades", affected))

	// err = json.NewEncoder(w).Encode(tradeRows)
	// if err != nil {
	// 	http.Error(w,
	// 		fmt.Sprintf("GetTrades produced the following error during encoding: %s.\n", err.Error()),
	// 		500)
	// 	return
	// }

	return

}

//if you want to find only the open trades that haven't been saved, pass true. Otherwise, pass false to get all trades.
func CompileTrades(save bool) ([]Trade, error) {

	var queryString string
	if save {
		queryString = `select orderId, symbol, instruction, amount, price, transactionDate  from tradeTransactions where tradeStatus = 'OPEN' order by symbol, transactionDate ASC;`
	} else {
		queryString = `select orderId, symbol, instruction, amount, price, transactionDate from tradeTransactions order by symbol, transactionDate ASC;`
	}
	rows, err := db.db.Query(queryString)
	if err != nil {
		return nil, fmt.Errorf("Failed to get rows: %s", err.Error())
	}

	defer rows.Close()
	var currentSymbol string
	tradeSlice := make([]TradeOrder, 0)
	tradeRows := make([]Trade, 0)
	var first = true
	for rows.Next() {
		var t = TradeOrder{}
		err := rows.Scan(&t.OrderId, &t.Symbol, &t.Instruction, &t.Quantity, &t.Price, &t.OrderDate)
		if err != nil {
			return nil, fmt.Errorf("Failed to scan row: %s", err.Error())
		}
		if first {
			currentSymbol = t.Symbol
			first = false
		}
		//when the symbol changes, we need to collect all of the data by symbol, so build the rows here:
		if currentSymbol != t.Symbol {
			currentSymbol = t.Symbol
			err := BuildTradeRow(tradeSlice, &tradeRows, 0)
			if err != nil {
				return nil, fmt.Errorf("Failed to getTradeRow %s", err.Error())
			}
			tradeSlice = nil
		}
		//empty the tradeSlice so we can build another symbol collection:
		tradeSlice = append(tradeSlice, t)
	}

	return tradeRows, nil
}

func BuildTradeRow(ts []TradeOrder, tSlice *[]Trade, pos int) error {

	var tradeRow = Trade{}
	tradeRow.Symbol = ts[pos].Symbol
	tradeRow.EntryPrice = ts[pos].Price
	tradeRow.OpenDate = ts[pos].OrderDate

	switch ts[pos].Instruction {
	case "BUY":
		tradeRow.TradeType = "LONG"
	case "SELL":
		tradeRow.TradeType = "SHORT"
	default:
		return fmt.Errorf("This isn't a buy or sell... symbol:%s orderDate:%s", tradeRow.Symbol, tradeRow.OpenDate)
	}

	var buyCount int
	var sellCount int
	var buyCost float64
	var sellCost float64
	for ; pos < len(ts); pos++ {
		tradeRow.OrderIdSlice = append(tradeRow.OrderIdSlice, ts[pos].OrderId)
		tradeRow.Executions += 1
		tradeRow.Quantity += int(ts[pos].Quantity)
		if ts[pos].Instruction == "BUY" {
			buyCount += int(ts[pos].Quantity)
			buyCost += (ts[pos].Price * ts[pos].Quantity)
		} else if ts[pos].Instruction == "SELL" {
			sellCount += int(ts[pos].Quantity)
			sellCost += (ts[pos].Price * ts[pos].Quantity)
		} else {
			return fmt.Errorf("Didn't find a sell or buy position for order: %v", ts[pos].OrderId)
		}

		if (tradeRow.TradeType == "LONG" && sellCount >= buyCount) || (tradeRow.TradeType == "SHORT" && buyCount >= sellCount) {
			//we have the hit the end of the trade. If there is more data in the array, we need to start a new order:
			tradeRow.TradeStatus = "CLOSED"
			tradeRow.ExitPrice = ts[pos].Price
			tradeRow.CloseDate = ts[pos].OrderDate
			tradeRow.ProfitLoss = sellCost - buyCost
			if tradeRow.TradeType == "LONG" {
				tradeRow.AvgEntryPrice = buyCost / float64(buyCount)
				tradeRow.AvgExitPrice = sellCost / float64(sellCount)
				tradeRow.PercentGain = ((tradeRow.AvgExitPrice - tradeRow.AvgEntryPrice) / tradeRow.AvgEntryPrice) * 100
			} else {
				tradeRow.AvgEntryPrice = sellCost / float64(sellCount)
				tradeRow.AvgExitPrice = buyCost / float64(buyCount)
				tradeRow.PercentGain = ((tradeRow.AvgEntryPrice - tradeRow.AvgExitPrice) / tradeRow.AvgEntryPrice) * 100
			}
			*tSlice = append(*tSlice, tradeRow)
			//if this is true, we are done and need to return.
			if len(ts) <= (pos + 1) {
				return nil
			}
			//if not, it means there is more data so we need to make another call:
			pos++
			err := BuildTradeRow(ts, tSlice, pos)
			if err != nil {
				return err
			}
			return nil
		}

		//check if this is the last element. This can happen if there is an open position that hasn't been closed:
		//if true, we are at the end and have an open position:``
		if len(ts) <= pos {
			tradeRow.TradeStatus = "OPEN"
			tradeRow.AvgEntryPrice = buyCost / float64(buyCount)
			*tSlice = append(*tSlice, tradeRow)
			return nil
		}
	}

	//we assume if we get here, we hit the end of the symbol list and this position hasn't been closed:
	tradeRow.TradeStatus = "OPEN"
	tradeRow.AvgEntryPrice = buyCost / float64(buyCount)
	*tSlice = append(*tSlice, tradeRow)
	return nil
}

func (h *TDHandlers) Quote(w http.ResponseWriter, req *http.Request) {
	ctx := context.Background()
	client, err := h.authenticator.AuthenticatedClient(ctx, req)
	if err != nil {
		http.Error(w, "Failed to authenticate", 401)
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

	renderTemplate(w, req, "home", nil)

}

func (h *TDHandlers) Movers(w http.ResponseWriter, req *http.Request) {
	ctx := context.Background()
	client, err := h.authenticator.AuthenticatedClient(ctx, req)
	if err != nil {
		http.Error(w, "Failed to authenticate", 401)
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

//NOT USED CURRENTLY:
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

func GetTradesForDayView(w http.ResponseWriter, r *http.Request) {

	var dateRaw = time.Now().Format("2006-01-02")

	dateInput := r.URL.Query().Get("date")

	//if we got a date from the user so need to parse it and serve that date:
	parsedDate, err := time.Parse("2006-01-02", dateInput)
	dateRaw = parsedDate.Format("2006-01-02")
	if err != nil {
		http.Error(w,
			fmt.Sprintf("Couldn't parse provided date. Must be format YYYY-MM-MM: %s", err.Error()),
			500,
		)
		return
	}

	var tradeSlice = make([]Trade, 0)

	data := struct {
		DateRaw      string
		TradeCount   int
		SharesTraded int
		ClosedGross  float64
		Trades       []Trade
		// TotalFees    float64
		// FinalPL      float64
	}{dateRaw, 0, 0, 0.0, tradeSlice}
	queryString := fmt.Sprintf("select * from tradeHistory where closeDate LIKE '%s%%' order by closeDate ASC;", dateRaw)
	rows, err := db.db.Query(queryString)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to query db: %s", err.Error()), 500)
		return
	}

	for rows.Next() {
		var t = Trade{}
		err := rows.Scan(&t.ID, &t.Symbol, &t.ProfitLoss, &t.Quantity, &t.EntryPrice, &t.ExitPrice, &t.OpenDate, &t.CloseDate, &t.TradeType, &t.AvgEntryPrice, &t.AvgExitPrice, &t.PercentGain, &t.Executions)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to scan rows: %s", err.Error()), 500)
			return
		}

		closeDate, err := time.Parse("2006-01-02T15:04:05-0700", t.CloseDate)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed parse time: %s", err.Error()), 400)
			return
		}

		if closeDate.Format("2006-01-02") == dateRaw {
			data.TradeCount += 1
			data.SharesTraded += t.Quantity
			data.ClosedGross += t.ProfitLoss
		}
		closeDate = timeToPST(closeDate)
		t.CloseDate = closeDate.Format(tableTimeFormat)
		data.Trades = append(data.Trades, t)
	}

	err = json.NewEncoder(w).Encode(data)
	if err != nil {
		http.Error(w,
			fmt.Sprintf("GetTrades produced the following error during encoding: %s.\n", err.Error()),
			500)
		return
	}

	return

}

type Event struct {
	Title   string `json:"title"`
	Date    string `json:"start"`
	Display string `json:"display"`
}

func GetEventsByQuery(w http.ResponseWriter, r *http.Request) {

	fmt.Println(r.URL.Path)

	name := strings.TrimPrefix(r.URL.Path, "/getEventsByQuery/")

	bs, err := ioutil.ReadFile(fmt.Sprintf("%s.sql", name))
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to open sql file: %s", err.Error()), 400)
		return
	}

	queryString := fmt.Sprintf(string(bs))
	rows, err := db.db.Query(queryString)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to query db: %s", err.Error()), 500)
		return
	}

	var events = make([]Event, 0)

	for rows.Next() {
		var e = Event{}
		e.Display = "background"
		err := rows.Scan(&e.Title, &e.Date)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to scan rows: %s", err.Error()), 500)
			return
		}

		events = append(events, e)
	}

	err = json.NewEncoder(w).Encode(events)
	if err != nil {
		http.Error(w,
			fmt.Sprintf("GetEvents produced the following error during encoding: %s.\n", err.Error()),
			500)
		return
	}
}

type TradeViewData struct {
	LoggedIn    bool
	Symbol      string
	PercentGain float64
	DisplayDate string
	StartDate   string
	EndDate     string
	Shares      int
	ProfitLoss  float64
	Callback    string
	Executions  []TradeOrder
}

func timeToPST(t time.Time) time.Time {

	loc, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		fmt.Println(err)
	}

	t = t.In(loc)

	return t
}

func RenderTradeDetail(w http.ResponseWriter, r *http.Request, tokenState bool) {

	tradeId := r.URL.Query().Get("id")
	callBackURL := r.URL.Query().Get("callback")

	bs, err := ioutil.ReadFile("sql/getTradeById.sql")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to open sql file: %s", err.Error()), 400)
		return
	}
	id, err := strconv.Atoi(tradeId)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to provide an int for the id: %v|%v", tradeId, err.Error()), 400)
		return
	}
	queryString := fmt.Sprintf(string(bs))

	var t = Trade{}
	err = db.db.QueryRow(queryString, id).Scan(&t.ID, &t.Symbol, &t.OpenDate, &t.CloseDate, &t.ProfitLoss, &t.Quantity, &t.PercentGain)
	if err != nil {
		http.Error(w, fmt.Sprintf("Couldn't get order for id: %v:%s", tradeId, err.Error()), 400)
		return
	}

	bs2, err := ioutil.ReadFile("sql/getTradeTransactions.sql")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to open sql file: %s", err.Error()), 400)
		return
	}

	queryString = fmt.Sprintf(string(bs2))

	rows, err := db.db.Query(queryString, t.OpenDate, t.CloseDate, t.Symbol)
	if err != nil {
		http.Error(w, fmt.Sprintf("Couldn't get rows for id: %v:%s", tradeId, err.Error()), 500)
		return
	}
	var tvd = TradeViewData{}
	tvd.LoggedIn = tokenState
	tvd.Symbol = t.Symbol
	closeDate, err := time.Parse("2006-01-02T15:04:05-0700", t.CloseDate)
	if err != nil {
		http.Error(w, "Failed to parse date from database", 500)
		return
	}
	closeDate = timeToPST(closeDate)
	tvd.DisplayDate = closeDate.Format("2 Jan 2006 15:04")
	tvd.StartDate = t.OpenDate
	tvd.EndDate = t.CloseDate
	tvd.Shares = t.Quantity
	tvd.ProfitLoss = t.ProfitLoss
	tvd.PercentGain = t.PercentGain
	tvd.Executions = make([]TradeOrder, 0)
	tvd.Callback = callBackURL

	defer rows.Close()
	for rows.Next() {
		var to = TradeOrder{}
		err = rows.Scan(&to.OrderDate, &to.Symbol, &to.Instruction, &to.Quantity, &to.Price)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to scan row: %s", err.Error()), 500)
			return
		}
		tmpTime, err := time.Parse(UTCTimeFormat, to.OrderDate)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to parse time from UTC %s", err.Error()), 500)
			return
		}
		tmpTime = timeToPST(tmpTime)
		to.OrderDate = tmpTime.Format(tableTimeFormat)
		tvd.Executions = append(tvd.Executions, to)
	}
	name := "tradeView"
	renderTemplate(w, r, name, tvd)

	return
}

const UTCTimeFormat = "2006-01-02T15:04:05-0700"
const tableTimeFormat = "02-01-2006 15:04:05"

//change this so it is simply a generic template loader:
func (h *TDHandlers) Templates(w http.ResponseWriter, r *http.Request) {

	name := strings.TrimPrefix(r.URL.Path, "/tpl/")
	fmt.Println(name)
	var tokenState bool

	ctx := context.Background()
	_, err := h.authenticator.AuthenticatedClient(ctx, r)
	if err == nil {
		tokenState = true
	}
	if name == "tradeView" {
		RenderTradeDetail(w, r, tokenState)
		return
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
			LoggedIn bool
			Date     string
			DateRaw  string
		}{tokenState, dateTime, dateRaw}

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
		Header template.HTML
		Body   template.HTML
		// LoggedIn bool
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
