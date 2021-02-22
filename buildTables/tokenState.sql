CREATE TABLE `tokenTable` (
  `accessToken` longtext,
  `refreshToken` longtext,
  `expiry` varchar(45) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
