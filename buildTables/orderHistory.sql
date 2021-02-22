CREATE TABLE `orderHistory` (
  `orderId` int(11) NOT NULL,
  `symbol` varchar(10) NOT NULL,
  `positionEffect` varchar(45) DEFAULT NULL,
  `instruction` varchar(10) DEFAULT NULL,
  `quantity` int(11) DEFAULT NULL,
  `price` decimal(14,2) DEFAULT NULL,
  `orderDate` varchar(30) DEFAULT NULL,
  `positionStatus` varchar(15) DEFAULT NULL,
  PRIMARY KEY (`orderId`),
  UNIQUE KEY `orderId_UNIQUE` (`orderId`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
