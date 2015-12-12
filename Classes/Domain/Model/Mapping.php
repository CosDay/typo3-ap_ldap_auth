<?php
namespace AP\ApLdapAuth\Domain\Model;

/**
 * LDAP configuration mapping model
 *
 * @package TYPO3
 * @subpackage tx_apldap_auth
 * @author Alexander Pankow <info@alexander-pankow.de>
 */
class Mapping extends \TYPO3\CMS\Extbase\DomainObject\AbstractEntity {

	/**
	 * @var bool
	 */
	protected $hidden;

	/**
	 * @var int
	 */
	protected $configUid;

	/**
	 * @var string
	 */
	protected $field;

	/**
	 * @var string
	 */
	protected $value;

	/**
	 * @var bool
	 */
	protected $isAttribute;

	/**
	 * @var boolean
	 */
	protected $isImage;

	/**
	 * @var boolean
	 */
	protected $isDatetime;

	/**
	 * @param boolean $hidden
	 */
	public function setHidden($hidden) {
		$this->hidden = $hidden;
	}

	/**
	 * @return boolean
	 */
	public function getHidden() {
		return $this->hidden;
	}

	/**
	 * @return int
	 */
	public function getConfigUid() {
		return $this->configUid;
	}

	/**
	 * @param int $configUid
	 */
	public function setConfigUid($configUid) {
		$this->configUid = $configUid;
	}

	/**
	 * @param string $field
	 */
	public function setField($field) {
		$this->field = $field;
	}

	/**
	 * @return string
	 */
	public function getField() {
		return $this->field;
	}

	/**
	 * @param string $value
	 */
	public function setValue($value) {
		$this->value = $value;
	}

	/**
	 * @return string
	 */
	public function getValue() {
		return $this->value;
	}

	/**
	 * @return string
	 */
	public function getAttribute()  {
		return $this->getValue();
	}

	/**
	 * @return boolean
	 */
	public function getIsAttribute() {
		return $this->isAttribute;
	}

	/**
	 * @param boolean $isAttribute
	 */
	public function setIsAttribute($isAttribute) {
		$this->isAttribute = $isAttribute;
	}

	/**
	 * @return boolean
	 */
	public function getIsImage() {
		return $this->isImage;
	}

	/**
	 * @param boolean $isImage
	 */
	public function setIsImage($isImage) {
		$this->isImage = $isImage;
	}

	/**
	 * @return boolean
	 */
	public function getIsDatetime() {
		return $this->isDatetime;
	}

	/**
	 * @param boolean $isDatetime
	 */
	public function setIsDatetime($isDatetime) {
		$this->isDatetime = $isDatetime;
	}
}
