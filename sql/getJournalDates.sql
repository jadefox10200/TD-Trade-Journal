select
  DATE(DATE_FORMAT(STR_TO_DATE(TransactionDate, '%Y-%m-%d'), '%Y-%m-%d')) as date
  from tradeTransactions
  group by date
  order by date desc
  LIMIT 30;
