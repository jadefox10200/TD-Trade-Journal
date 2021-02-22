CREATE TABLE `tradeHistory` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `symbol` varchar(10) NOT NULL,
  `profitLoss` decimal(14,2) DEFAULT NULL,
  `quantity` int(11) DEFAULT NULL,
  `entryPrice` decimal(14,2) DEFAULT NULL,
  `exitPrice` decimal(14,2) DEFAULT NULL,
  `openDate` varchar(30) DEFAULT NULL,
  `closeDate` varchar(30) DEFAULT NULL,
  `tradeType` varchar(10) DEFAULT NULL,
  `avgEntryPrice` decimal(14,2) DEFAULT NULL,
  `avgExitPrice` decimal(14,2) DEFAULT NULL,
  `percentGain` decimal(14,2) DEFAULT NULL,
  `executions` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `id_UNIQUE` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=704 DEFAULT CHARSET=latin1;
