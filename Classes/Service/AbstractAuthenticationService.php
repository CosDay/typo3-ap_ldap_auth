<?php
namespace AP\ApLdapAuth\Sv;

use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Abstract authentication service which initializes parts of extbase framework to use repositories in authentication services
 *
 * @package TYPO3
 * @subpackage tx_apldapauth
 * @author Alexander Pankow <info@alexander-pankow.de>
 */
abstract class AbstractAuthenticationService extends \TYPO3\CMS\Sv\AbstractAuthenticationService {

	/**
	 * @var \TYPO3\CMS\Extbase\Configuration\ConfigurationManagerInterface
	 */
	protected $configurationManager;

	/**
	 * @var \TYPO3\CMS\Extbase\Object\ObjectManagerInterface
	 */
	protected $objectManager;

	/**
	 * @var \TYPO3\CMS\Core\Cache\CacheManager
	 */
	protected $cacheManager;

	/**
	 * @var \TYPO3\CMS\Extbase\Reflection\ReflectionService
	 */
	protected $reflectionService;

	/**
	 * @var \TYPO3\CMS\Extbase\Persistence\Generic\PersistenceManager
	 */
	protected $persistenceManager;

	/**
	 * @var TypoScriptService
	 */
	protected $typoScriptService;

	/**
	 * @return boolean
	 */
	public function init() {
		// extbase bootstrap
		$this->objectManager = GeneralUtility::makeInstance('TYPO3\\CMS\\Extbase\\Object\\ObjectManager');
		$this->typoScriptService = $this->objectManager->get('AP\\ApLdapAuth\\Sv\\TypoScriptService');
		$this->initializeRequiredTsfeParts();
		$this->initializeExtbaseFramework();
		$this->initTCA();

		return parent::init();
	}

	/**
	 * @return void
	 */
	protected function initializeRequiredTsfeParts() {
		if (!isset($GLOBALS['TSFE']) || empty($GLOBALS['TSFE']->sys_page)) {
			$GLOBALS['TSFE']->sys_page = GeneralUtility::makeInstance('TYPO3\\CMS\\Frontend\\Page\\PageRepository');
		}
		if (!isset($GLOBALS['TSFE']) || empty($GLOBALS['TSFE']->tmpl)) {
			$GLOBALS['TSFE']->tmpl = GeneralUtility::makeInstance('TYPO3\\CMS\\Core\\TypoScript\\TemplateService');
		}
	}

	/**
	 * @return void
	 */
	protected function initializeExtbaseFramework() {
		// initialize cache manager
		$this->cacheManager = $GLOBALS['typo3CacheManager'];

		// inject content object into the configuration manager
		$this->configurationManager = $this->objectManager->get('TYPO3\\CMS\\Extbase\\Configuration\\ConfigurationManagerInterface');
		$contentObject = GeneralUtility::makeInstance('TYPO3\\CMS\\Frontend\\ContentObject\\ContentObjectRenderer');
		$this->configurationManager->setContentObject($contentObject);

		$this->typoScriptService->makeTypoScriptBackup();
		// load extbase typoscript
		TypoScriptService::loadTypoScriptFromFile('EXT:extbase/ext_typoscript_setup.txt');
		TypoScriptService::loadTypoScriptFromFile('EXT:ap_ldap_auth/ext_typoscript_setup.txt');
		$this->configurationManager->setConfiguration($GLOBALS['TSFE']->tmpl->setup);
		$this->configureObjectManager();

		// initialize reflection
		$this->reflectionService = $this->objectManager->get('TYPO3\\CMS\\Extbase\\Reflection\\ReflectionService');
		$this->reflectionService->setDataCache($this->cacheManager->getCache('extbase_reflection'));
		if (!$this->reflectionService->isInitialized())
			$this->reflectionService->initialize();

		// initialize persistence
		$this->persistenceManager = $this->objectManager->get('TYPO3\\CMS\\Extbase\\Persistence\\Generic\\PersistenceManager');
	}

	/**
	 * @return void
	 */
	protected function configureObjectManager() {
		$typoScriptSetup = $this->configurationManager->getConfiguration(\TYPO3\CMS\Extbase\Configuration\ConfigurationManagerInterface::CONFIGURATION_TYPE_FULL_TYPOSCRIPT);
		if (!is_array($typoScriptSetup['config.']['tx_extbase.']['objects.'])) {
			return;
		}
		$objectContainer = GeneralUtility::makeInstance('TYPO3\\CMS\\Extbase\\Object\\Container\\Container');
		foreach ($typoScriptSetup['config.']['tx_extbase.']['objects.'] as $classNameWithDot => $classConfiguration) {
			if (isset($classConfiguration['className'])) {
				$originalClassName = rtrim($classNameWithDot, '.');
				$objectContainer->registerImplementation($originalClassName, $classConfiguration['className']);
			}
		}
	}

	/**
	 * Initializes TCA configuration array
	 */
	protected function initTCA() {
		if (!is_array($GLOBALS['TCA']) || !isset($GLOBALS['TCA']['pages']))
			\TYPO3\CMS\Core\Core\Bootstrap::getInstance()->loadCachedTca();
	}

	/**
	 * @return array|boolean
	 */
	public function getUser() {
		$value = $this->_getUser();
		$this->typoScriptService->restoreTypoScriptBackup();
		return $value;
	}

	/**
	 * @param array $user
	 * @return integer|boolean
	 */
	public function authUser(array $user) {
		$value = $this->_authUser($user);
		$this->typoScriptService->restoreTypoScriptBackup();
		return $value;
	}

	/**
	 * @return array|boolean
	 */
	abstract protected function _getUser();

	/**
	 * @param array $user
	 * @return integer|boolean
	 */
	abstract protected function _authUser(array $user);
}
