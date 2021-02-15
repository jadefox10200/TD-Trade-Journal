SELECT SUM(profitLoss) AS title,
FROM_DAYS(TO_DAYS(closeDate) -MOD(TO_DAYS(closeDate) -1, 7)) AS title

   FROM tradeHistory
  GROUP BY FROM_DAYS(TO_DAYS(closeDate) -MOD(TO_DAYS(closeDate) -1, 7))
  ORDER BY FROM_DAYS(TO_DAYS(closeDate) -MOD(TO_DAYS(closeDate) -1, 7))
