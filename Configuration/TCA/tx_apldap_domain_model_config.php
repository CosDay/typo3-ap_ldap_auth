<?php
if (!defined ('TYPO3_MODE')) die ('Access denied.');

$extKey = 'ap_ldap_auth';
$extPath = \TYPO3\CMS\Core\Utility\ExtensionManagementUtility::extRelPath($extKey);

return \TYPO3\CMS\Core\Utility\GeneralUtility::array_merge_recursive_overrule($GLOBALS['TCA']['tx_apldap_domain_model_config'], array(
	'interface' => array(
		'showRecordFieldList' => $GLOBALS['TCA']['tx_ldap_domain_model_config']['interface']['showRecordFieldList'] . ',be_users_base_dn,be_users_filter,be_users_mapping,be_groups_base_dn,be_groups_filter,be_groups_mapping,fe_users_base_dn,fe_users_filter,fe_users_mapping,fe_groups_base_dn,fe_groups_filter,fe_groups_mapping'
	),
	'columns' => array(
		'be_users_base_dn' => array(
			'exclude' => 1,
			'label' => 'LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldap_domain_model_config.be_users_base_dn',
			'config' => array(
				'type' => 'input',
				'size' => '30',
				'eval' => 'trim',
			)
		),
		'be_users_filter' => array(
			'exclude' => 1,
			'label' => 'LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldap_domain_model_config.be_users_filter',
			'config' => array(
				'type' => 'input',
				'size' => '30',
				'eval' => 'trim',
			)
		),
		'be_users_mapping' => array(
			'exclude' => 1,
			'label' => 'LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldap_domain_model_config.be_users_mapping',
			'config' => array(
				'type' => 'text',
				'eval' => 'trim',
			)
		),
		'be_groups_base_dn' => array(
			'exclude' => 1,
			'label' => 'LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldap_domain_model_config.be_groups_base_dn',
			'config' => array(
				'type' => 'input',
				'size' => '30',
				'eval' => 'trim',
			)
		),
		'be_groups_filter' => array(
			'exclude' => 1,
			'label' => 'LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldap_domain_model_config.be_groups_filter',
			'config' => array(
				'type' => 'input',
				'size' => '30',
				'eval' => 'trim',
			)
		),
		'be_groups_mapping' => array(
			'exclude' => 1,
			'label' => 'LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldap_domain_model_config.be_groups_mapping',
			'config' => array(
				'type' => 'text',
				'eval' => 'trim',
			)
		),
		'fe_users_base_dn' => array(
			'exclude' => 1,
			'label' => 'LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldap_domain_model_config.fe_users_base_dn',
			'config' => array(
				'type' => 'input',
				'size' => '30',
				'eval' => 'trim',
			)
		),
		'fe_users_filter' => array(
			'exclude' => 1,
			'label' => 'LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldap_domain_model_config.fe_users_filter',
			'config' => array(
				'type' => 'input',
				'size' => '30',
				'eval' => 'trim',
			)
		),
		'fe_users_mapping' => array(
			'exclude' => 1,
			'label' => 'LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldap_domain_model_config.fe_users_mapping',
			'config' => array(
				'type' => 'inline',
				'foreign_table' => 'tx_apldapauth_domain_model_mapping',
				'foreign_field' => 'config_uid'
			)
		),
		'fe_groups_base_dn' => array(
			'exclude' => 1,
			'label' => 'LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldap_domain_model_config.fe_groups_base_dn',
			'config' => array(
				'type' => 'input',
				'size' => '30',
				'eval' => 'trim',
			)
		),
		'fe_groups_filter' => array(
			'exclude' => 1,
			'label' => 'LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldap_domain_model_config.fe_groups_filter',
			'config' => array(
				'type' => 'input',
				'size' => '30',
				'eval' => 'trim',
			)
		),
		'fe_groups_mapping' => array(
			'exclude' => 1,
			'label' => 'LLL:EXT:' . $extKey . '/Resources/Private/Language/locallang_db.xml:tx_apldap_domain_model_config.fe_groups_mapping',
			'config' => array(
				'type' => 'text',
				'eval' => 'trim',
			)
		)
	)
));

