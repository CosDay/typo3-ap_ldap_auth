<?php
namespace AP\ApLdapAuth\Sv;

use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Service to make backup of current TypoScript and restore it. Used in authentication service.
 *
 * @package TYPO3
 * @subpackage tx_apldapauth
 * @author Alexander Pankow <info@alexander-pankow.de>
 */
class TypoScriptService implements \TYPO3\CMS\Core\SingletonInterface {

	/**
	 * @var array
	 */
	protected $typoScriptBackup;

	/**
	 * @param string $filePath
	 * @return void
	 */
	public static function loadTypoScriptFromFile($filePath) {
		static $typoScriptParser;
		$filePath = GeneralUtility::getFileAbsFileName($filePath);
		if ($filePath) {
			if ($typoScriptParser === null)
				$typoScriptParser = GeneralUtility::makeInstance('TYPO3\\CMS\\Core\\TypoScript\\Parser\\TypoScriptParser');

			/* @var \TYPO3\CMS\Core\TypoScript\Parser\TypoScriptParser $typoScriptParser */
			$typoScript = file_get_contents($filePath);
			if ($typoScript) {
				$typoScriptParser->parse($typoScript);
				$typoScriptArray = $typoScriptParser->setup;
				if (is_array($typoScriptArray) && !empty($typoScriptArray)) {
					$GLOBALS['TSFE']->tmpl->setup = GeneralUtility::array_merge_recursive_overrule($typoScriptArray, $GLOBALS['TSFE']->tmpl->setup);
				}
			}
		}
	}

	/**
	 * @return void
	 */
	public function makeTypoScriptBackup() {
		$this->typoScriptBackup = array();
		foreach ($GLOBALS['TSFE']->tmpl->setup as $key => $value) {
			$this->typoScriptBackup[$key] = $value;
		}
	}

	/**
	 * @return void
	 */
	public function restoreTypoScriptBackup() {
		if ($this->hasTypoScriptBackup()) {
			$GLOBALS['TSFE']->tmpl->setup = $this->typoScriptBackup;
		}
	}

	/**
	 * @return boolean
	 */
	public function hasTypoScriptBackup() {
		return is_array($this->typoScriptBackup) && !empty($this->typoScriptBackup);
	}
}
