CREATE TABLE `tradeNoteTable` (
  `tradeId` int(11) NOT NULL,
  `noteData` longtext,
  `noteDate` varchar(30) DEFAULT NULL,
  PRIMARY KEY (`tradeId`),
  UNIQUE KEY `tradeId_UNIQUE` (`tradeId`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
