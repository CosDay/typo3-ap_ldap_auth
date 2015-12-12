#
# Table structure for table 'tx_apldap_domain_model_config'
#
CREATE TABLE tx_apldap_domain_model_config (
		be_users_base_dn tinytext NOT NULL,
		be_users_filter tinytext NOT NULL,
		be_users_mapping text NOT NULL,
		be_groups_base_dn tinytext NOT NULL,
		be_groups_filter tinytext NOT NULL,
		be_groups_mapping tinytext NOT NULL,
		fe_users_base_dn tinytext NOT NULL,
		fe_users_filter tinytext NOT NULL,
		fe_users_mapping text NOT NULL,
		fe_groups_base_dn tinytext NOT NULL,
		fe_groups_filter tinytext NOT NULL,
		fe_groups_mapping tinytext NOT NULL
);

#
# Table structure for table 'tx_apldap_domain_model_mapping'
#
CREATE TABLE tx_apldapauth_domain_model_mapping (
		uid int(11) NOT NULL auto_increment,
		pid int(11) DEFAULT '0' NOT NULL,
		tstamp int(11) DEFAULT '0' NOT NULL,
		crdate int(11) DEFAULT '0' NOT NULL,
		cruser_id int(11) DEFAULT '0' NOT NULL,
		deleted tinyint(4) DEFAULT '0' NOT NULL,
		hidden tinyint(4) DEFAULT '0' NOT NULL,
		config_uid int(11) DEFAULT '0' NOT NULL,
		field varchar(255) DEFAULT '' NOT NULL,
		value varchar(255) DEFAULT '' NOT NULL,
		is_attribute tinyint(1) DEFAULT '1' NOT NULL,
		is_image tinyint(1) DEFAULT '0' NOT NULL,
		is_datetime tinyint(1) DEFAULT '0' NOT NULL,
		type varchar(20) DEFAULT '0' NOT NULL,
		PRIMARY KEY (uid),
		KEY parent (pid)
);

#
# Table structure for table 'be_groups'
#
CREATE TABLE be_groups (
	tx_apldapauth_dn tinytext NOT NULL
);

#
# Table structure for table 'be_users'
#
CREATE TABLE be_users (
		tx_apldapauth_dn tinytext NOT NULL
);

#
# Table structure for table 'fe_groups'
#
CREATE TABLE fe_groups (
		tx_apldapauth_dn tinytext NOT NULL
);

#
# Table structure for table 'fe_users'
#
CREATE TABLE fe_users (
		tx_apldapauth_dn tinytext NOT NULL
);
