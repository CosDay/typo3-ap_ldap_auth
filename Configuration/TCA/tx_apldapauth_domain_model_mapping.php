<?php
/**
 * @var $TCA
 */
if (!defined ('TYPO3_MODE')) {
	die ('Access denied.');
}

$extKey = 'ap_ldap_auth';
$extPath = \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::extRelPath($extKey);

return array(
	'ctrl' => array(
		'title' => 'LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldapauth_domain_model_mapping.title',
		'label' => 'value',
		'label_userFunc' => 'AP\ApLdapAuth\Utility\LDAPMappingUtility->labelUserFunc_getLabel',
		'type' => 'type',
		'hideTable' => true,
		'adminOnly' => true,
		'rootLevel' => 1,
		'dividers2tabs' => true,
		'tstamp' => 'tstamp',
		'crdate' => 'crdate',
		'cruser_id' => 'cruser_id',
		'default_sortby' => 'ORDER BY uid',
		'delete' => 'deleted',
		'enablecolumns' => array(
			'disabled' => 'hidden'
		),
		'iconfile' => $extPath . 'ext_icon.gif'
	),
	'interface' => array(
		'showRecordFieldList' => 'hidden,type,field,value,is_attribute,is_image,is_datetime'
	),
	'columns' => array(
		'hidden' => array(
			'exclude' => 1,
			'label' => 'LLL:EXT:lang/locallang_general.xml:LGL.hidden',
			'config' => array(
				'type' => 'check',
				'default' => '0'
			)
		),
		'type' => array(
			'exclude' => 1,
			'label' => 'LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldapauth_domain_model_mapping.type',
			'config' => array(
				'type' => 'select',
				'items' => array(
					array('fe_users', 'fe_users')
				),
				'default' => 'fe_users'
			)
		),
		'field' => array(
			'exclude' => 1,
			'label' => 'LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldapauth_domain_model_mapping.field',
			'config' => array(
				'type' => 'select',
				'itemsProcFunc' => 'AP\ApLdapAuth\Utility\LDAPMappingUtility->itemsProcFunc_getFieldItems',
				'size' => 1,
				'maxitems' => 1,
			)
		),
		'value' => array(
			'exclude' => 1,
			'label' => 'LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldapauth_domain_model_mapping.value',
			'config' => array(
				'type' => 'input',
				'size' => '20',
				'eval' => 'trim,required',
			)
		),
		'is_attribute' => array(
			'exclude' => 1,
			'label' => 'LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldapauth_domain_model_mapping.is_attribute',
			'config' => array(
				'type' => 'check',
				'default' => '1',
				'items' => array(
					array('LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldapauth_domain_model_mapping.yes', 1)
				)
			)
		),
		'is_image' => array(
			'exclude' => 1,
			'label' => 'LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldapauth_domain_model_mapping.is_image',
			'config' => array(
				'type' => 'check',
				'default' => '0',
				'items' => array(
					array('LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldapauth_domain_model_mapping.yes', 1)
				)
			)
		),
		'is_datetime' => array(
			'exclude' => 1,
			'label' => 'LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldapauth_domain_model_mapping.is_datetime',
			'config' => array(
				'type' => 'check',
				'default' => '0',
				'items' => array(
					array('LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldapauth_domain_model_mapping.yes', 1)
				)
			)
		),
	),
	'palettes' => array(
		'general' => array(
			'showitem' => '
				--div--;LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldap_domain_model_config.tabs.general,type,hidden'
		),
		'mapping' => array(
			'showitem' => '
				--div--;LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldapauth_domain_model_mapping.title,field,value'
		),
		'checkboxes' => array(
			'showitem' => '
				--div--,is_attribute,is_image,is_datetime'
		)
	),
	'types' => array(
		'fe_users' => array(
			'showitem' => '
				--palette--;;general,
				--palette--;;mapping,
				--palette--;;checkboxes
				'
		)
	)
);

