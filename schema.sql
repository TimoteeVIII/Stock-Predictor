CREATE DATABASE IF NOT EXISTS `pythonlogin`;

CREATE TABLE IF NOT EXISTS `accounts` (
	`id` int(11) NOT NULL AUTO_INCREMENT,
  	`username` varchar(50) NOT NULL,
  	`password` varchar(255) NOT NULL,
  	`email` varchar(100) NOT NULL,
    PRIMARY KEY (`id`)
);

CREATE TABLE IF NOT EXISTS `investments` (
	`id` int(11) NOT NULL AUTO_INCREMENT,
	`user_id` int(11) NOT NULL,
	`company` varchar(50) NOT NULL,
	`shares_bought` decimal(9,2) NOT NULL,
	`money_invested` decimal(9,2) NOT NULL,
	`cost_per_share` decimal(9,2) NOT NULL,
	PRIMARY KEY (`id`)
);