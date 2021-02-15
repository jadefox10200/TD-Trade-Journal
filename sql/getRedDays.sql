select * from (
select sum(profitLoss) AS title, SUBSTRING_INDEX(closeDate, 'T', 1) AS date from tradeHistory
group by date
) as profit where title < 0
order by date DESC;
