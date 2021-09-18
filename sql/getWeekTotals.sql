SELECT SUM(profitLoss) AS Title, FROM_DAYS(TO_DAYS(STR_TO_DATE(closeDate, '%Y-%m-%d')) -MOD(TO_DAYS(STR_TO_DATE(closeDate, '%Y-%m-%d')) -1, 7)) AS Date FROM tradeHistory
  GROUP BY FROM_DAYS(TO_DAYS(STR_TO_DATE(closeDate, '%Y-%m-%d')) -MOD(TO_DAYS(STR_TO_DATE(closeDate, '%Y-%m-%d')) -1, 7))
  ORDER BY FROM_DAYS(TO_DAYS(STR_TO_DATE(closeDate, '%Y-%m-%d')) -MOD(TO_DAYS(STR_TO_DATE(closeDate, '%Y-%m-%d')) -1, 7));
