<?php
namespace AP\ApLdapAuth\Domain\Repository;

use AP\ApLdap\Exception\LDAPException,
	TYPO3\CMS\Core\Utility\GeneralUtility,
	AP\ApLdap\Utility\LDAPUtility,
	AP\ApLdapAuth\Utility\LDAPConfigUtility,
	AP\ApLdapAuth\Domain\Model\Mapping\FeUsers;

/**
 * Repository for LDAP frontend users
 *
 * @package TYPO3
 * @subpackage tx_apldapauth
 * @author Alexander Pankow <info@alexander-pankow.de>
 */
class LDAPFEUserRepository extends \AP\ApLdapAuth\Persistence\LdapRepository {

	/**
	 * @param int $configId
	 * @param string $filter
	 * @param array $attributes
	 * @return array
	 * @throws \AP\ApLdap\Exception\ConnectionException
	 */
	public function getAllUsers($configId = 0, $filter = '', $attributes = array()) {
		$ldapConnections = $this->getLDAPConnectionsByConfigId($configId);

		$users = array();
		foreach ($ldapConnections as $ldapConnection) {
			if (empty($filter))
				$filter = $this->getFeUsersFilter($ldapConnection, '*');
			$baseDn = $ldapConnection->getConfig()->getFeUsersBaseDn();
			$search = $ldapConnection->search($baseDn, $filter, $attributes);
			while ($entry = $search->getNextEntry()) {
				$dn = $entry->getDN();
				foreach ($entry->getAttributes() as $attribute) {
					$attribute = strtolower($attribute);
					$users[$dn][$attribute] = $entry->getValues($attribute);
					$user[$dn]['configId'] = $ldapConnection->getConfigUid();
				}
			}
		}

		return $users;
	}

	/**
	 * Returns user by uid
	 *
	 * @param string $username
	 * @param int $configId
	 * @return array|boolean
	 */
	public function getUserByUsernameField($username, $configId = 0) {
		$ldapConnections = $this->getLDAPConnectionsByConfigId($configId);

		$user = false;
		foreach ($ldapConnections as $ldapConnection) {
			try {
				$filter = $this->getFeUsersFilter($ldapConnection, ldap_escape($username));
				$entry = $ldapConnection->search($ldapConnection->getDN(), $filter)->getFirstEntry();
			} catch (LDAPException $e) {
				continue;
			}

			if (!empty($entry)) {
				foreach ($entry->getAttributes() as $attribute) {
					$attribute = strtolower($attribute);
					$user[$attribute] = $entry->getValues($attribute);
				}
				$user['dn'] = $entry->getDN();
				$user['configId'] = $ldapConnection->getConfigUid();
			}
		}

		return $user;
	}

	/**
	 * Returns the name of the ldap attribute that is mapped to a given typo3 field
	 *
	 * @param string $t3FieldName
	 * @param int $configId
	 * @return bool|string		False if no attribute is found
	 */
	public function getLDAPAttributeByTypo3FieldName($t3FieldName, $configId = 0) {
		$ldapConnections = $this->getLDAPConnectionsByConfigId($configId);

		foreach ($ldapConnections as $ldapConnection) {
			$feUserMapping = $ldapConnection->getConfig()->getFeUsersMapping();
			/** @var $mapping FeUsers */
			foreach ($feUserMapping as $mapping) {
				if (!$mapping->getIsAttribute())
					continue;

				$typo3FieldName = $mapping->getField();
				if ($typo3FieldName == $t3FieldName)
					return strtolower($mapping->getAttribute());
			}
		}
		return false;
	}

	/**
	 * Check if user exists and we can bind to the user
	 *
	 * @param $username
	 * @param $password
	 * @return array|bool
	 */
	public function checkUser($username, $password) {
		$result = false;
		foreach ($this->getLDAPConnections() as $ldapConnection) {
			$filter = $this->getFeUsersFilter($ldapConnection, $username);
			$baseDn = $ldapConnection->getConfig()->getFeUsersBaseDn();
			$search = $ldapConnection->search($baseDn, $filter)->getFirstEntry();

			// try to bind as found user
			if ($search->countEntries() > 0) {
				$entry = $search->getLastEntry();
				$ldapUser = array();
				foreach ($search->getAttributes() as $attribute) {
					$attribute = strtolower($attribute);
					$imageField = LDAPConfigUtility::getImageAttribute($ldapConnection->getConfig()->getFeUsersMapping());

					if (empty($imageField) || $attribute != $imageField)
						$ldapUser[$attribute] = $search->getValues($attribute);
					else if (!isset($ldapUser[$attribute]))
						$ldapUser[$attribute] = $search->getBinaryValues($attribute);
				}
				$ldapUser['dn'] = $username = $search->getDN($entry);
				try {
					if ($ldapConnection->bind($username, $password)) {
						$result = array(
							'ldapUser' => $ldapUser,
							'config' => $ldapConnection->getConfig()
						);
					}
				} catch (LDAPException $e) {
					GeneralUtility::sysLog($e->getMessage(), 'ap_ldap_auth', GeneralUtility::SYSLOG_SEVERITY_ERROR);
				}
			}
		}

		return $result;
	}

	/**
	 * Returns ldap connection(s) by config id
	 *
	 * @param int $configId
	 * @return \AP\ApLdap\Utility\LDAPUtility[]|array
	 */
	protected function getLDAPConnectionsByConfigId($configId = 0) {
		if ($configId > 0)
			$ldapConnections =  array($this->getLDAPConnection($configId));
		else
			$ldapConnections = $this->getLDAPConnections();
		return $ldapConnections;
	}

	/**
	 * Returns frontend users filter with username placeholder replaced
	 *
	 * @param LDAPUtility $ldapConnection
	 * @param string $placeholderReplacement
	 * @return string
	 */
	protected function getFeUsersFilter(LDAPUtility $ldapConnection, $placeholderReplacement = '*') {
		return str_replace('<username>', $placeholderReplacement, $ldapConnection->getConfig()->getFeUsersFilter());
	}
}
