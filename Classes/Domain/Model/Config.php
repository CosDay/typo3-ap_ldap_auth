<?php
namespace AP\ApLdapAuth\Domain\Model;

use \TYPO3\CMS\Extbase\Persistence\ObjectStorage;

/**
 * LDAP configuration model with mapping configurations
 *
 * @package TYPO3
 * @subpackage tx_apldapauth
 * @author Alexander Pankow <info@alexander-pankow.de>
 */
class Config extends \AP\ApLdap\Domain\Model\Config {

	/**
	 * @var string
	 */
	protected $beUsersBaseDn;

	/**
	 * @var string
	 */
	protected $beUsersFilter;

	/**
	 * @var \AP\ApLdapAuth\Domain\Model\Mapping
	 */
	protected $beUsersMapping;

	/**
	 * @var string
	 */
	protected $beGroupsBaseDn;

	/**
	 * @var string
	 */
	protected $beGroupsFilter;

	/**
	 * @var \TYPO3\CMS\Extbase\Persistence\ObjectStorage<\AP\ApLdapAuth\Domain\Model\Mapping>
	 */
	protected $beGroupsMapping;

	/**
	 * @var string
	 */
	protected $feUsersBaseDn;

	/**
	 * @var string
	 */
	protected $feUsersFilter;

	/**
	 * @var \TYPO3\CMS\Extbase\Persistence\ObjectStorage<\AP\ApLdapAuth\Domain\Model\Mapping\FeUsers>
	 */
	protected $feUsersMapping;

	/**
	 * @var string
	 */
	protected $feGroupsBaseDn;

	/**
	 * @var string
	 */
	protected $feGroupsFilter;

	/**
	 * @var \TYPO3\CMS\Extbase\Persistence\ObjectStorage<\AP\ApLdapAuth\Domain\Model\Mapping>
	 */
	protected $feGroupsMapping;

	/**
	 * @param string $beGroupsBaseDn
	 */
	public function setBeGroupsBaseDn($beGroupsBaseDn) {
		$this->beGroupsBaseDn = $beGroupsBaseDn;
	}

	/**
	 * @return string
	 */
	public function getBeGroupsBaseDn() {
		return $this->beGroupsBaseDn;
	}

	/**
	 * @param string $beGroupsFilter
	 */
	public function setBeGroupsFilter($beGroupsFilter) {
		$this->beGroupsFilter = $beGroupsFilter;
	}

	/**
	 * @return string
	 */
	public function getBeGroupsFilter() {
		return $this->beGroupsFilter;
	}

	/**
	 * @param string $beGroupsMapping
	 */
	public function setBeGroupsMapping($beGroupsMapping) {
		$this->beGroupsMapping = $beGroupsMapping;
	}

	/**
	 * @return ObjectStorage
	 */
	public function getBeGroupsMapping() {
		return $this->beGroupsMapping;
	}

	/**
	 * @param string $beUsersBaseDn
	 */
	public function setBeUsersBaseDn($beUsersBaseDn) {
		$this->beUsersBaseDn = $beUsersBaseDn;
	}

	/**
	 * @return string
	 */
	public function getBeUsersBaseDn() {
		return $this->beUsersBaseDn;
	}

	/**
	 * @param string $beUsersFilter
	 */
	public function setBeUsersFilter($beUsersFilter) {
		$this->beUsersFilter = $beUsersFilter;
	}

	/**
	 * @return string
	 */
	public function getBeUsersFilter() {
		return $this->beUsersFilter;
	}

	/**
	 * @param ObjectStorage $beUsersMapping
	 */
	public function setBeUsersMapping(ObjectStorage $beUsersMapping) {
		$this->beUsersMapping = $beUsersMapping;
	}

	/**
	 * @return ObjectStorage
	 */
	public function getBeUsersMapping() {
		return $this->beUsersMapping;
	}

	/**
	 * @param string $feGroupsBaseDn
	 */
	public function setFeGroupsBaseDn($feGroupsBaseDn) {
		$this->feGroupsBaseDn = $feGroupsBaseDn;
	}

	/**
	 * @return string
	 */
	public function getFeGroupsBaseDn() {
		return $this->feGroupsBaseDn;
	}

	/**
	 * @param string $feGroupsFilter
	 */
	public function setFeGroupsFilter($feGroupsFilter) {
		$this->feGroupsFilter = $feGroupsFilter;
	}

	/**
	 * @return string
	 */
	public function getFeGroupsFilter() {
		return $this->feGroupsFilter;
	}

	/**
	 * @param ObjectStorage $feGroupsMapping
	 */
	public function setFeGroupsMapping(ObjectStorage $feGroupsMapping) {
		$this->feGroupsMapping = $feGroupsMapping;
	}

	/**
	 * @return ObjectStorage
	 */
	public function getFeGroupsMapping() {
		return $this->feGroupsMapping;
	}

	/**
	 * @param string $feUsersBaseDn
	 */
	public function setFeUsersBaseDn($feUsersBaseDn) {
		$this->feUsersBaseDn = $feUsersBaseDn;
	}

	/**
	 * @return string
	 */
	public function getFeUsersBaseDn() {
		return $this->feUsersBaseDn;
	}

	/**
	 * @param string $feUsersFilter
	 */
	public function setFeUsersFilter($feUsersFilter) {
		$this->feUsersFilter = $feUsersFilter;
	}

	/**
	 * @return string
	 */
	public function getFeUsersFilter() {
		return $this->feUsersFilter;
	}

	/**
	 * @param ObjectStorage $feUsersMapping
	 */
	public function setFeUsersMapping(ObjectStorage $feUsersMapping) {
		$this->feUsersMapping = $feUsersMapping;
	}

	/**
	 * @return ObjectStorage
	 */
	public function getFeUsersMapping() {
		return $this->feUsersMapping;
	}
}
