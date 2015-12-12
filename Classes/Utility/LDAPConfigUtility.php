<?php
namespace AP\ApLdapAuth\Utility;

/**
 * LDAP config utility for LDAP configuration
 *
 * @package TYPO3
 * @subpackage tx_apldapauth
 * @author Alexander Pankow <info@alexander-pankow.de>
 */
class LDAPConfigUtility {

	/**
	 * @param null $filter
	 * @return string
	 */
	public static function getUsernameAttribute($filter = null) {
		if ($filter && preg_match("'([^$]*)\\(([^$]*)=<username>\\)'", $filter, $username))
			return $username[2];

		return '';
	}

	/**
	 * @param \TYPO3\CMS\Extbase\Persistence\ObjectStorage $mapping
	 * @return string
	 */
	public static function getImageAttribute(\TYPO3\CMS\Extbase\Persistence\ObjectStorage &$mapping) {
		/** @var $field \AP\ApLdapAuth\Domain\Model\Mapping\FeUsers */
		foreach ($mapping as $field) {
			if ($field->getIsImage())
				return $field->getField();
		}

		return '';
	}
}
