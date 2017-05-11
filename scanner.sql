-- phpMyAdmin SQL Dump
-- version 4.6.6deb4
-- https://www.phpmyadmin.net/
--
-- Host: localhost:3306
-- Generation Time: May 11, 2017 at 08:40 AM
-- Server version: 5.7.18-0ubuntu0.17.04.1
-- PHP Version: 7.0.18-0ubuntu0.17.04.1

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `scanner`
--

-- --------------------------------------------------------

--
-- Table structure for table `exceptions`
--

CREATE TABLE `exceptions` (
  `exceptionkey` int(11) NOT NULL,
  `IP_Address` varchar(32) NOT NULL,
  `Plugin` int(11) NOT NULL,
  `First_Discovered` varchar(32) NOT NULL,
  `Except_Until` date NOT NULL,
  `Excepted_By` varchar(128) NOT NULL,
  `Description` text NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `hosts`
--

CREATE TABLE `hosts` (
  `hostkey` int(11) NOT NULL,
  `hostname` varchar(128) DEFAULT NULL,
  `IP_Address` varchar(30) DEFAULT NULL,
  `MAC_Address` varchar(30) DEFAULT NULL,
  `DNS_Name` varchar(128) DEFAULT NULL,
  `NetBIOS_Name` varchar(128) DEFAULT NULL,
  `Description` varchar(1023) DEFAULT NULL,
  `First_Discovered` varchar(32) DEFAULT NULL,
  `Scan_Date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=latin1;


-- --------------------------------------------------------

--
-- Table structure for table `plugins`
-- Store information about used Nessus plugins

CREATE TABLE `plugins` (
  `Plugin` bigint(20) NOT NULL,
  `Plugin_Name` varchar(128) DEFAULT NULL,
  `Family` varchar(128) DEFAULT NULL,
  `Severity` varchar(30) DEFAULT NULL,
  `Protocol` varchar(12) DEFAULT NULL,
  `Port` int(11) DEFAULT NULL,
  `Exploit` varchar(8) DEFAULT NULL,
  `Repository` varchar(30) DEFAULT NULL,
  `Plugin_Text` text,
  `Synopsis` text,
  `Description` text,
  `Solution` text,
  `See_Also` varchar(1023) DEFAULT NULL,
  `Risk_Factor` varchar(30) DEFAULT NULL,
  `STIG_Severity` varchar(30) DEFAULT NULL,
  `CVSS_Base_Score` int(11) DEFAULT NULL,
  `CVSS_Temporal_Score` int(11) DEFAULT NULL,
  `CVSS_Vector` varchar(128) DEFAULT NULL,
  `CPE` varchar(128) DEFAULT NULL,
  `CVE` varchar(128) DEFAULT NULL,
  `BID` varchar(128) DEFAULT NULL,
  `Cross_References` varchar(255) DEFAULT NULL,
  `Mitigated_On` varchar(32) DEFAULT NULL,
  `Vuln_Publication_Date` varchar(32) DEFAULT NULL,
  `Patch_Publication_Date` varchar(32) DEFAULT NULL,
  `Plugin_Publication_Date` varchar(32) DEFAULT NULL,
  `Plugin_Modification_Date` varchar(32) DEFAULT NULL,
  `Exploit_Ease` varchar(128) DEFAULT NULL,
  `Exploit_Frameworks` varchar(128) DEFAULT NULL,
  `Check_Type` varchar(30) DEFAULT NULL,
  `Version` varchar(30) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `scans`
--

CREATE TABLE `scans` (
  `ScanKey` int(11) NOT NULL,
  `Plugin` varchar(32) NOT NULL,
  `IP_Address` varchar(30) DEFAULT NULL,
  `MAC_Address` varchar(30) DEFAULT NULL,
  `DNS_Name` varchar(128) DEFAULT NULL,
  `NetBios_Name` varchar(32) NOT NULL,
  `Scan_Date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `First_Discovered` varchar(32) DEFAULT NULL,
  `Mitigated_On` varchar(32) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `hosts`
--
ALTER TABLE `hosts`
  ADD PRIMARY KEY (`hostkey`);

--

-- Indexes for table `plugins`
--
ALTER TABLE `plugins`
  ADD PRIMARY KEY (`Plugin`),
  ADD KEY `Plugin` (`Plugin`);

--
-- Indexes for table `scans`
--
ALTER TABLE `scans`
  ADD UNIQUE KEY `Scankey_idx` (`ScanKey`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `hosts`
--
ALTER TABLE `hosts`
  MODIFY `hostkey` int(11) NOT NULL AUTO_INCREMENT;
--

-- AUTO_INCREMENT for table `scans`
--
ALTER TABLE `scans`
  MODIFY `ScanKey` int(11) NOT NULL AUTO_INCREMENT;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
