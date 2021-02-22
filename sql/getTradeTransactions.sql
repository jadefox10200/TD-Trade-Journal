select
-- STR_TO_DATE(transactionDate, '%%Y-%%m-%%dT%%H:%%i:%%s') as dateTime,
transactionDate as dateTime,
symbol, instruction, amount as quantity, price from tradeTransactions
where transactionDate >= ? and transactionDate <= ? and symbol = ?
ORDER BY transactionDate asc;
