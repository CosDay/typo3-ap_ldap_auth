<?php
$extensionPath = \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::extPath('ap_ldap_auth');
return array(
	'AP\\ApLdapAuth\\Sv\\TypoScriptService' => $extensionPath . 'Classes/Service/TypoScriptService.php',
);
