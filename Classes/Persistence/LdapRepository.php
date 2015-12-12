<?php
namespace AP\ApLdapAuth\Persistence;

use AP\ApLdap\Exception\LDAPException,
	AP\ApLdap\Utility\LDAPUtility,
	TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Base repository for LDAP
 *
 * @package TYPO3
 * @subpackage tx_apldapauth
 * @author Alexander Pankow <info@alexander-pankow.de>
 */
class LdapRepository implements \TYPO3\CMS\Core\SingletonInterface {

	/**
	 * @var array
	 */
	protected $extConfig;

	/**
	 * @var LDAPUtility[]
	 */
	protected $ldapConnections = array();

	/**
	 * @var \TYPO3\CMS\Extbase\Object\ObjectManagerInterface
	 */
	protected $objectManager = null;

	/**
	 * Constructs a new Repository for LDAP
	 *
	 * @param \TYPO3\CMS\Extbase\Object\ObjectManagerInterface $objectManager
	 */
	public function __construct(\TYPO3\CMS\Extbase\Object\ObjectManagerInterface $objectManager = null) {
		if ($objectManager === null)
			$this->objectManager = \TYPO3\CMS\Core\Utility\GeneralUtility::makeInstance('TYPO3\\CMS\\Extbase\\Object\\ObjectManager');
		else
			$this->objectManager = $objectManager;

		$this->extConfig = unserialize($GLOBALS['TYPO3_CONF_VARS']['EXT']['extConf']['ap_ldap_auth']);
		if (empty($this->extConfig['feLoginConfigurationUids'])) {
			// use default configuration from `ap_ldap` extension
			$this->createLDAPConnection();
		} else {
			// not-default configuration used
			$configUids = explode(',', $this->extConfig['feLoginConfigurationUids']);
			foreach ($configUids as $configUid) {
				$this->createLDAPConnection($configUid);
			}
		}
	}

	/**
	 * @return LDAPUtility[]
	 */
	public function getLDAPConnections() {
		return $this->ldapConnections;
	}

	/**
	 * @param int $configId
	 * @return LDAPUtility|null
	 */
	public function getLDAPConnection($configId) {
		if (isset($this->ldapConnections[$configId]))
			return $this->ldapConnections[$configId];

		return null;
	}

	/**
	 * @return array
	 */
	public function getExtConfig() {
		return $this->extConfig;
	}

	/**
	 * @param int $configUid	ID of configuration, if 0 default configuration from extension `ap_ldap` is used.
	 */
	protected function createLDAPConnection($configUid = 0) {
		try {
			/** @var \AP\ApLdap\Utility\LDAPUtility $connection */
			$connection = $this->objectManager->get('AP\\ApLdap\\Utility\\LDAPUtility');
			$connection->setConfigRepository('AP\\ApLdapAuth\\Domain\\Repository\\ConfigRepository');
			$connection->connect($configUid); // connect to server
			$connection->bind(); // bind with default data
			$this->ldapConnections[$connection->getConfigUid()] = $connection;
		} catch (LDAPException $e) {
			GeneralUtility::sysLog($e->getMessage(), 'ap_ldap_auth', GeneralUtility::SYSLOG_SEVERITY_ERROR);
		}
	}
}
