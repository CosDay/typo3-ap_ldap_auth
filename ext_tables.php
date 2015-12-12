<?php
/**
 * @var $_EXTKEY
 * @var $TCA
 */
if (!defined ('TYPO3_MODE')) die ('Access denied.');

// extend show item of table tx_apldap_domain_model_config (columns are added in TCA config file)
/*$TCA['tx_apldap_domain_model_config']['types'][0]['showitem'] .= ',
--div--;LLL:EXT:' . $_EXTKEY . '/Resources/Private/Language/locallang_db.xml:tx_apldap_domain_model_config.tabs.be_users, be_users_base_dn, be_users_filter, be_users_mapping,
--div--;LLL:EXT:' . $_EXTKEY . '/Resources/Private/Language/locallang_db.xml:tx_apldap_domain_model_config.tabs.be_groups, be_groups_base_dn, be_groups_filter, be_groups_mapping,
--div--;LLL:EXT:' . $_EXTKEY . '/Resources/Private/Language/locallang_db.xml:tx_apldap_domain_model_config.tabs.fe_users,fe_users_base_dn, fe_users_filter, fe_users_mapping,
--div--;LLL:EXT:' . $_EXTKEY . '/Resources/Private/Language/locallang_db.xml:tx_apldap_domain_model_config.tabs.fe_groups,fe_groups_base_dn, fe_groups_filter, fe_groups_mapping';*/
$TCA['tx_apldap_domain_model_config']['types'][0]['showitem'] .= ',
--div--;LLL:EXT:' . $_EXTKEY . '/Resources/Private/Language/locallang_db.xml:tx_apldap_domain_model_config.tabs.fe_users,fe_users_base_dn, fe_users_filter, fe_users_mapping';
