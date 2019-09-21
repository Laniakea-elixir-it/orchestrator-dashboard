CREATE DATABASE  IF NOT EXISTS `orchestrator_dashboard`
USE `orchestrator_dashboard`;

--
-- Table structure for table `deployments`
--

DROP TABLE IF EXISTS `deployments`;
CREATE TABLE `deployments` (
  `uuid` varchar(36) NOT NULL,
  `creation_time` datetime DEFAULT NULL,
  `update_time` datetime DEFAULT NULL,
  `physicalId` varchar(36) DEFAULT NULL,
  `description` varchar(256) DEFAULT NULL,
  `status` varchar(128) DEFAULT NULL,
  `outputs` mediumtext,
  `task` varchar(64) DEFAULT NULL,
  `links` mediumtext,
  `sub` varchar(36) DEFAULT NULL,
  `provider_name` varchar(128) DEFAULT NULL,
  `endpoint` varchar(256) DEFAULT NULL,
  `template` longtext,
  `inputs` mediumtext,
  `params` mediumtext,
  `locked` tinyint(1) DEFAULT '0',
  `feedback_required` tinyint(1) DEFAULT '1',
  `remote` tinyint(1) DEFAULT '0',
  `issuer` varchar(256) DEFAULT NULL,
  `storage_encryption` TINYINT(1) DEFAULT '0',
  `vault_secret_uuid` VARCHAR(36) DEFAULT NULL,
  `vault_secret_key` VARCHAR(32) DEFAULT NULL,
  `status_reason` VARCHAR(256) DEFAULT NULL,
  PRIMARY KEY (`uuid`)
);

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `sub` varchar(36) NOT NULL,
  `name` varchar(128) DEFAULT NULL,
  `username` varchar(64) NOT NULL,
  `given_name` varchar(64) DEFAULT NULL,
  `family_name` varchar(64) DEFAULT NULL,
  `email` varchar(64) NOT NULL,
  `organisation_name` varchar(64) DEFAULT NULL,
  `picture` varchar(128) DEFAULT NULL,
  `role` varchar(32) DEFAULT 'user',
  `active` tinyint(1) DEFAULT '1',
  `sshkey` varchar(2048) DEFAULT NULL,
  PRIMARY KEY (`sub`)
);

