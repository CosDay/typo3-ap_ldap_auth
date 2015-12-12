<?php
namespace AP\ApLdapAuth\Utility;

use TYPO3\CMS\Extbase\Utility\LocalizationUtility;

class LDAPMappingUtility implements \TYPO3\CMS\Core\SingletonInterface {

	/**
	 * @param array $params
	 * @param $pObj
	 */
	public function labelUserFunc_getLabel(&$params, $pObj) {
		$record = \TYPO3\CMS\Backend\Utility\BackendUtility::getRecord($params['table'], $params['row']['uid']);
		if (!empty($record['type']) && !empty($record['field']) && !empty($record['value'])) {
			$newTitle = "$record[type].$record[field] = ";
			if (!empty($record['is_attribute']))
				$newTitle .= "<span style=\"color: #05a;\">" . $record['value'] . "</span>";
			else
				$newTitle .= "<span style=\"color: #a11;\">\"$record[value]\"</span>";
		} else {
			$newTitle = "<em>(" . LocalizationUtility::translate('LLL:EXT:ap_ldap_auth/Resources/Private/Language/locallang_db.xml:tx_apldapauth_domain_model_mapping.new_mapping', 'ap_ldap_auth') . ")</em>";
		}
		$params['title'] = $newTitle;
	}

	/**
	 * @param array $params
	 * @param $pObj
	 */
	public function itemsProcFunc_getFieldItems(&$params, $pObj) {
		$type = $params['row']['type'];
		if (empty($type))
			return;

		$columns = $GLOBALS['TCA'][$type]['columns'];
		$items = array();
		foreach ($columns as $column => $columnConfig)
			$items[$column] = $column;

		// add some fields manually
		$items['pid'] = 'pid';
		ksort($items);

		foreach ($items as $key => $item)
			$params['items'][] = array($item, $key);
	}
}
