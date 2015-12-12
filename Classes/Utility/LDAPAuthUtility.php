<?php
namespace AP\ApLdapAuth\Utility;

use AP\ApLdapAuth\Domain\Model\Mapping\FeUsers,
	AP\ApLdapAuth\Domain\Model\Config;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * LDAP auth utility to fetch and create users and groups from LDAP
 *
 * @package TYPO3
 * @subpackage tx_apldapauth
 * @author Alexander Pankow <info@alexander-pankow.de>
 */
class LDAPAuthUtility implements \TYPO3\CMS\Core\SingletonInterface {

	/**
	 * @var \AP\ApLdapAuth\Domain\Repository\LDAPFeUserRepository|null
	 */
	protected $ldapFeUserRepository = null;

	/**
	 * LDAP configuration of found user
	 *
	 * @var Config|null
	 */
	protected $currentConfig = null;

	/**
	 * @var \TYPO3\CMS\Extbase\Object\ObjectManagerInterface
	 */
	protected $objectManager = null;

	/**
	 * @param \TYPO3\CMS\Extbase\Object\ObjectManagerInterface $objectManager
	 */
	public function __construct(\TYPO3\CMS\Extbase\Object\ObjectManagerInterface $objectManager = null) {
		if ($objectManager === null)
			$this->objectManager = \TYPO3\CMS\Core\Utility\GeneralUtility::makeInstance('TYPO3\\CMS\\Extbase\\Object\\ObjectManager');
		else
			$this->objectManager = $objectManager;
	}

	/**
	 * @see \AP\ApLdapAuth\Domain\Repository\LDAPFeUserRepository::checkUser()
	 * @param $username
	 * @param $password
	 * @return array|bool
	 */
	public function checkUser($username, $password) {
		switch (TYPO3_MODE) {
			case 'FE':
				$result = $this->getLdapFeUserRepository()->checkUser($username, $password);
				if (!empty($result['config']))
					$this->currentConfig = $result['config'];
				return $result['ldapUser'];
			case 'BE':
				return false;
		}

		return false;
	}

	/**
	 * Synchronize user from LDAP directory with TYPO3 database
	 *
	 * @param array $ldapUser
	 * @return array|null
	 */
	public function synchronizeUser(array $ldapUser) {
		$userData = $this->getTypo3UserData($ldapUser);

		// get user from database
		$user = $this->selectUser($userData);

		if (!$user) {
			// create user
			$user = $this->importUser($userData);
		} else {
			// update user
			$user = $this->updateUser($userData);
		}

		return $user;
	}

	/**
	 * Gets user from TYPO3 database
	 *
	 * @param array $userData
	 * @return array|null
	 */
	public function selectUser(array $userData) {
		$user = $this->getTypo3DbConnection()->exec_SELECTgetRows(
			'*',
			TYPO3_MODE === 'BE' ? 'be_users' : 'fe_users',
			'tx_apldapauth_dn = ' . $this->getTypo3DbConnection()->fullQuoteStr($userData['tx_apldapauth_dn'], TYPO3_MODE === 'BE' ? 'be_users' : 'fe_users')
		);
		return $user[0];
	}

	/**
	 * Import user from LDAP directory into TYPO3 database
	 *
	 * @param array $userData
	 * @return array|null
	 */
	public function importUser(array $userData) {
		$this->getTypo3DbConnection()->exec_INSERTquery(
			TYPO3_MODE === 'BE' ? 'be_users' : 'fe_users',
			$userData
		);

		return $this->selectUser($userData);
	}

	/**
	 * Updates user in TYPO3 database by data from LDAP directory
	 *
	 * @param array $userData
	 * @return array|null
	 */
	public function updateUser(array $userData) {
		$this->getTypo3DbConnection()->exec_UPDATEquery(
			TYPO3_MODE === 'BE' ? 'be_users' : 'fe_users',
			'tx_apldapauth_dn = ' . $this->getTypo3DbConnection()->fullQuoteStr($userData['tx_apldapauth_dn'], TYPO3_MODE === 'BE' ? 'be_users' : 'fe_users'),
			$userData
		);

		return $this->selectUser($userData);
	}

	/**
	 * Get the data for TYPO3 database
	 *
	 * @param array $ldapUser
	 * @return array
	 */
	public function getTypo3UserData(array $ldapUser) {
		$mappings = $this->currentConfig->getFeUsersMapping();

		// generate random password
		$charSet = 'abdeghjmnpqrstuvxyzABDEGHJLMNPQRSTVWXYZ23456789@#$%';
		$password = '';
		for ($i = 0; $i < 16; $i++)
			$password .= $charSet[(rand() % strlen($charSet))];

		$usernameAttribute = LDAPConfigUtility::getUsernameAttribute($this->currentConfig->getFeUsersFilter());
		$typo3UserData = array(
			'username' => $ldapUser[$usernameAttribute][0],
			'tx_apldapauth_dn' => $ldapUser['dn'],
			'pid' => 0,
			'password' => $password
		);
		unset($mappings['pid']);

		/** @var $mapping FeUsers */
		foreach ($mappings as $mapping) {
			$typo3FieldName = $mapping->getField();
			$ldapAttribute = strtolower($mapping->getAttribute());
			$value = $mapping->getIsAttribute() ? $ldapUser[$ldapAttribute][0] : $mapping->getValue();
			if ($mapping->getIsImage()) {
				// image
				$fileName = 'tx_apldapauth_' . md5($typo3UserData['tx_apldapauth_dn']) . '.jpg';
				$imageFilePath = PATH_site . 'uploads/pics/' . $fileName;
				$image = imagecreatefromstring($value);
				$imageSaveSuccess = imagejpeg($image, $imageFilePath);
				if ($imageSaveSuccess) $typo3UserData[$typo3FieldName] = $fileName;
			} else if ($mapping->getIsDatetime()) {
				// date fields
				$typo3UserData[$typo3FieldName] = strtotime($value);
			} else {
				// text fields
				$typo3UserData[$typo3FieldName] = $value; // use value of $ldapFieldName if field in $ldapUser doesn't exist
			}
		}

		return $typo3UserData;
	}

	/**
	 * @return \AP\ApLdapAuth\Domain\Repository\LDAPFeUserRepository|null
	 */
	protected function getLdapFeUserRepository() {
		if ($this->ldapFeUserRepository === null)
			$this->ldapFeUserRepository = $this->objectManager->get('AP\\ApLdapAuth\\Domain\\Repository\\LDAPFeUserRepository');
		return $this->ldapFeUserRepository;
	}

	/**
	 * @return \TYPO3\CMS\Dbal\Database\DatabaseConnection
	 */
	protected function getTypo3DbConnection() {
		return $GLOBALS['TYPO3_DB'];
	}
}
