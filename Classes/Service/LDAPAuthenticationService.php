<?php
namespace AP\ApLdapAuth\Sv;

use AP\ApLdapAuth\Utility\LDAPAuthUtility;
use TYPO3\CMS\Core\Utility\GeneralUtility;

require_once \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::extPath('ap_ldap_auth') . 'Classes/Service/AbstractAuthenticationService.php';

/**
 * Authentication service for LDAP directories
 *
 * @package TYPO3
 * @subpackage tx_apldapauth
 * @author Alexander Pankow <info@alexander-pankow.de>
 */
class LDAPAuthenticationService extends AbstractAuthenticationService {

	/**
	 * @var \AP\ApLdapAuth\Utility\LDAPAuthUtility
	 */
	protected $ldapAuth;

	/**
	 * @return boolean
	 */
	public function init() {
		$return = parent::init();

		$this->ldapAuth = $this->objectManager->get('AP\\ApLdapAuth\\Utility\\LDAPAuthUtility');

		return $return;
	}

	/**
	 * @return array|boolean
	 */
	public function _getUser() {
		$user = false;
		if ($this->login['status'] === 'login') {
			if ($this->login['uident']) {
				if ($ldapUser = $this->ldapAuth->checkUser($this->login['uname'], $this->login['uident_text'])) {
					// synchronize ldap user with typo3 database
					$user = $this->ldapAuth->synchronizeUser($ldapUser);
					$user['tx_apldapauth_from'] = 'LDAP';
				} else {
					// database fallback
					$user = $this->fetchUserRecord($this->login['uname']);
				}

				if (!is_array($user)) {
					// Failed login attempt (no username found)
					$this->writelog(255, 3, 3, 2,
									"Login-attempt from %s (%s), username '%s' not found!!",
									array($this->authInfo['REMOTE_ADDR'], $this->authInfo['REMOTE_HOST'], $this->login['uname'])); // Logout written to log
					// Logout written to log
					GeneralUtility::sysLog(sprintf('Login-attempt from %s (%s), username \'%s\' not found!', $this->authInfo['REMOTE_ADDR'], $this->authInfo['REMOTE_HOST'], $this->login['uname']), 'tx_apldap_auth', \TYPO3\CMS\Core\Utility\GeneralUtility::SYSLOG_SEVERITY_WARNING);
				} else {
					// user found
					if ($this->writeDevLog) {
						GeneralUtility::devLog('User found: ' . GeneralUtility::arrayToLogString($user, array($this->db_user['userid_column'], $this->db_user['username_column'])), 'tx_apldap_auth');
					}
				}
			} else {
				// Failed Login attempt (no password given)
				$this->writelog(255, 3, 3, 2, 'Login-attempt from %s (%s) for username \'%s\' with an empty password!', array($this->authInfo['REMOTE_ADDR'], $this->authInfo['REMOTE_HOST'], $this->login['uname']));
				\TYPO3\CMS\Core\Utility\GeneralUtility::sysLog(sprintf('Login-attempt from %s (%s), for username \'%s\' with an empty password!', $this->authInfo['REMOTE_ADDR'], $this->authInfo['REMOTE_HOST'], $this->login['uname']), 'Core', \TYPO3\CMS\Core\Utility\GeneralUtility::SYSLOG_SEVERITY_WARNING);
			}
		}

		return $user;
	}

	/**
	 * Authenticate a user (Check various conditions for the user that might invalidate its authentication, eg. password match, domain, IP, etc.)
	 *
	 * @param array $user	The user data
	 * @return int|bool		200 - authenticated and no more checking needed - useful for IP checking without password
	 *						100 - Just go on. User is not authenticated but there's still no reason to stop.
	 *						false - this service was the right one to authenticate the user but it failed
	 *						true - this service was able to authenticate the user
	 */
	public function _authUser(array $user) {
		$OK = 100;
		if ($this->login['uident'] && $this->login['uname']) {
			// database fallback
			$OK = isset($user['tx_apldapauth_from']) ? 200 : $this->compareUident($user, $this->login);

			// Failed login attempt (wrong password) - write that to the log!
			if (!$OK) {
				if ($this->writeAttemptLog) {
					$this->writelog(255, 3, 3, 1, 'Login-attempt from %s (%s), username \'%s\', password not accepted!', array($this->authInfo['REMOTE_ADDR'], $this->authInfo['REMOTE_HOST'], $this->login['uname']));
					\TYPO3\CMS\Core\Utility\GeneralUtility::sysLog(sprintf('Login-attempt from %s (%s), username \'%s\', password not accepted!', $this->authInfo['REMOTE_ADDR'], $this->authInfo['REMOTE_HOST'], $this->login['uname']), 'Core', \TYPO3\CMS\Core\Utility\GeneralUtility::SYSLOG_SEVERITY_WARNING);
				}
				if ($this->writeDevLog) {
					\TYPO3\CMS\Core\Utility\GeneralUtility::devLog('Password not accepted: ' . $this->login['uident'], 'TYPO3\\CMS\\Sv\\AuthenticationService', 2);
				}
			}

			// Checking the domain (lockToDomain)
			if ($OK && $user['lockToDomain'] && $user['lockToDomain'] != $this->authInfo['HTTP_HOST']) {
				// Lock domain didn't match, so error:
				if ($this->writeAttemptLog) {
					$this->writelog(255, 3, 3, 1, 'Login-attempt from %s (%s), username \'%s\', locked domain \'%s\' did not match \'%s\'!', array($this->authInfo['REMOTE_ADDR'], $this->authInfo['REMOTE_HOST'], $user[$this->db_user['username_column']], $user['lockToDomain'], $this->authInfo['HTTP_HOST']));
					\TYPO3\CMS\Core\Utility\GeneralUtility::sysLog(sprintf('Login-attempt from %s (%s), username \'%s\', locked domain \'%s\' did not match \'%s\'!', $this->authInfo['REMOTE_ADDR'], $this->authInfo['REMOTE_HOST'], $user[$this->db_user['username_column']], $user['lockToDomain'], $this->authInfo['HTTP_HOST']), 'Core', \TYPO3\CMS\Core\Utility\GeneralUtility::SYSLOG_SEVERITY_WARNING);
				}
				$OK = FALSE;
			}
		}

		return $OK;
	}
}
