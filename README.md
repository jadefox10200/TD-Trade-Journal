# TD

TD is a Trade Journal that is meant to be used with the broker TD Ameritrade.

# SET UP
After downloading, to set it up there are a few things that must be done to get it working:

First, you must build the main.go file. Because of this, you must have Go on your system. With that said, it is recommended you download with the following: 

``go get -v -u github.com/jadefox10200/TD-Trade-Journal``

Once you have that, you can go to the folder where it downloaded and run ``go build`` from your terminal.

You need a Mysql database. The default user is set to root. It is assumed you know how to use a mysql database or can get one.
Run the queries in the buildTables folder (starting with the createSchema) in
order to set up the needed tables.

Then you must set the following environment variables:
DBLOGIN
TDAMERITRADE_CLIENT_ID
TDAMERITRADE_ACCT_ID

The DBLOGIN must be set to whatever password you have set for the MYSQL database.
The TDAMERITRADE_CLIENT_ID must be obtained from TD Ameritrade. In order to get the client id, you must go to the TD Ameritrade API page: 
https://developer.tdameritrade.com/apis

There you must create an account and create an app. On that note, when setting up an application on the TD Ameritrade API site, you can call your
application whatever you like. However, for the app to work with TD-Trade-Journal you must set the callback url to:

http://localhost/callback

During authentication, there is a bug where when you go to log in via the TD Trade Journal you will get a 404 error. This is because TD Ameritrade is sending the callback to https. Simply go into the url address bar and you will see that it has routed to https://localhost....

Remove the 's' so it is http://localhost.... and then hit enter. This will log you in and the app will work from there. I know what you're thinking. "Shouldn't the author have simply implemented an https server so this doesn't happen?" The answer is yes. But I didn't. Use at your own risk.

# USAGE:

The only page that requires you to be logged in is the 'Import Transactions' page.
This is where you will import your transactions from TD Ameritrade. The simpilest
way to do this is to select whatever date range you like and click 'Load Transactions'.

This will show you all transactions for the time period you have selected and you
can see if everything makes sense. At this point, nothing has been saved.

Next click 'Save Transactions'. This downloads all of the transactions that you
see. You should then get a pop up showing how many transactions were saved.
In some cases, you may get 0 transactions saved. This will happen if you've already
saved those transactions. The app will not download the same transaction twice so
as to prevent duplicates.

Finally, click 'Save Trades'. The app will now compile all of your transactions
into round trip trades. With this done, you should now be able to review all of your
trades.

Some of these steps can sometimes take a few minutes to download depending on
how much data you are requesting. This is due to TD Ameritrade request limiters
and that the app downloads 3 charts for every round trip trade. Intraday charts
are not available for trades done prior to the year you are currently in. This
is a limitation from TD Ameritrade as far as I can tell. So if you are downloading
trades today in 2021 for example, you won't be able to view intraday charts for
trades done in 2020. But you will at least still get the 3 month, 6 month and
yearly chart view.

(/pics/importPage.png)

Also, the application supports mp4 daily trade review. To implement this, create
a folder in the main directory name 'AV'. In that folder you can have one video
per trading day. The format must be 'YYYY-MM-DD.mp4'. This assume you are either
recording your trading day or you are recording a trading day review for yourself.
You do not HAVE to implement this feature and it won't show up, unless you put
the folder there with videos inside it.

At this time, you should only need to log into TD Ameritrade once every 90 days.
The auth tokens are stored locally in the MySQL database. These are NOT encrypted
at this time.

I built it for my own use. Therefore this app is AS IS. Use it at your own risk.

With that being said, here are some pics of the app in use should you make it this far: 

(/pics/dayPage.png)
(/pics/homePage.png)
(/pics/importPage.png)
(/pics/monthPage.png)
(/pics/tablePage.png)
(/pics/videoPage.png)
