<?php
/**
 * @var $_EXTKEY
 */
if (!defined ("TYPO3_MODE")) die ('Access denied.');

\TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addService($_EXTKEY, 'auth', 'AP\\LDAPAuthenticationService', array(
	'title' => 'LDAP authentication',
	'description' => 'Authenticates users against a LDAP directory server.',
	'subtype' => 'getUserFE,authUserFE',
//	'subtype' => 'getUserBE,authUserBE,getUserFE,authUserFE,getGroupsFE,processLoginDataBE,processLoginDataFE',
	'available' => true,
	'priority' => 100,
	'quality' => 100,
	'os' => '',
	'exec' => '',
	'classFile' => \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::extPath($_EXTKEY).'Classes/Service/LDAPAuthenticationService.php',
	'className' => '\\AP\\ApLdapAuth\\Sv\\LDAPAuthenticationService'
));

//$GLOBALS['TYPO3_CONF_VARS']['SC_OPTIONS']['t3lib/class.t3lib_userauth.php']['logoff_pre_processing'][] = 'EXT:' . $_EXTKEY . '/Classes/Hook/LogoffHook.php:&LogoffHook->pre_processing';
