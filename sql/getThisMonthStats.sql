select
	DATE(DATE_FORMAT(STR_TO_DATE(closeDate, '%Y-%m-%d'), '%Y-%m-01')) AS month_beginning,
	COUNT(*) AS trades,
	TRUNCATE(sum(profitLoss)/count(*),2) as 'avgProfit',
	TRUNCATE(sum(percentGain)/count(*),2) as 'avgPercent',
	sum(profitLoss) as 'gi',
	sum(profitLoss > 0)/count(*) AS winPercent,
	sum(profitLoss < 0)/count(*) as 'lossPercent',
	max(profitLoss) as bigWinner,
	min(profitLoss) as bigLoser
from tradeHistory
group by month_beginning
order by month_beginning DESC
limit 1;
