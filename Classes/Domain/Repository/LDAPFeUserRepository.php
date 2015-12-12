<?php
namespace AP\ApLdapAuth\Domain\Repository;

use AP\ApLdap\Exception\LDAPException,
	TYPO3\CMS\Core\Utility\GeneralUtility,
	AP\ApLdapAuth\Utility\LDAPConfigUtility;

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
		if ($configId > 0)
			$ldapConnections =  array($this->getLDAPConnection($configId));
		else
			$ldapConnections = $this->getLDAPConnections();

		$users = array();
		foreach ($ldapConnections as $ldapConnection) {
			if (empty($filter))
				$filter = str_replace('<username>', '*', $ldapConnection->getConfig()->getFeUsersFilter());
			$baseDn = $ldapConnection->getConfig()->getFeUsersBaseDn();
			$search = $ldapConnection->search($baseDn, $filter, $attributes);
			while ($entry = $search->getNextEntry()) {
				$dn = $entry->getDN();
				foreach ($entry->getAttributes() as $attribute) {
					$users[$dn][$attribute] = $entry->getValues($attribute);
				}
			}
		}

		return $users;
	}

	/**
	 * @param string $dn
	 * @param int $configId
	 * @return array|boolean
	 */
	public function getUserByDn($dn, $configId = 0) {
		if ($configId > 0)
			$ldapConnections =  array($this->getLDAPConnection($configId));
		else
			$ldapConnections = $this->getLDAPConnections();

		$user = false;
		foreach ($ldapConnections as $ldapConnection) {
			try {
				$entry = $ldapConnection->search($dn, '(objectClass=cosdayUser)')->getFirstEntry();
			} catch (LDAPException $e) {
				continue;
			}

			foreach ($entry->getAttributes() as $attribute)
				$user[$attribute] = $entry->getValues($attribute);
		}

		return $user;
	}

	/**
	 * Check if user exists
	 *
	 * @param $username
	 * @param $password
	 * @return array|bool
	 */
	public function checkUser($username, $password) {
		$result = false;
		foreach ($this->getLDAPConnections() as $ldapConnection) {
			$filter = str_replace('<username>', $username, $ldapConnection->getConfig()->getFeUsersFilter());
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
}
