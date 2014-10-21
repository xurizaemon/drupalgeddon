<?php
/**
 * @file
 * Drupal site_audit integration.
 */

class SiteAuditCheckSecurityDrupalgeddonUsers extends SiteAuditCheckAbstract {
  /**
   * Implements \SiteAudit\Check\Abstract\getLabel().
   */
  public function getLabel() {
    return dt('Drupalgeddon users');
  }

  /**
   * Implements \SiteAudit\Check\Abstract\getDescription().
   */
  public function getDescription() {
    return dt('Check for known Drupalgeddon users in the user table.');
  }

  /**
   * Implements \SiteAudit\Check\Abstract\getResultFail().
   */
  public function getResultFail() {
    $user_list = array();
    foreach ($this->registry['drupalgeddon_users'] as $uid => $name) {
      $user_list[] = '#' . $uid . ': ' . $name;
    }
    return dt('The following users have been detected: @drupalgeddon_users', array(
      '@drupalgeddon_users' => implode(', ', $user_list),
    ));
  }

  /**
   * Implements \SiteAudit\Check\Abstract\getResultInfo().
   */
  public function getResultInfo() {}

  /**
   * Implements \SiteAudit\Check\Abstract\getResultPass().
   */
  public function getResultPass() {
    return dt('No known Drupalgeddon users were detected.');
  }

  /**
   * Implements \SiteAudit\Check\Abstract\getResultWarn().
   */
  public function getResultWarn() {}

  /**
   * Implements \SiteAudit\Check\Abstract\getAction().
   */
  public function getAction() {
    if ($this->score == SiteAuditCheckAbstract::AUDIT_CHECK_SCORE_FAIL) {
      return dt('Delete the offending users from your site and check for other malicious activity.');
    }
  }

  /**
   * Implements \SiteAudit\Check\Abstract\calculateScore().
   */
  public function calculateScore() {
    require_once DRUPALGEDDON_BASE_PATH . '/checks/bad_users_check.inc';
    $this->registry['drupalgeddon_users'] = bad_users_check_query();
    if (count($this->registry['drupalgeddon_users']) > 0) {
      return SiteAuditCheckAbstract::AUDIT_CHECK_SCORE_FAIL;
    }
    return SiteAuditCheckAbstract::AUDIT_CHECK_SCORE_PASS;
  }
}

class SiteAuditCheckSecurityDrupalgeddonRoles extends SiteAuditCheckAbstract {
  /**
   * Implements \SiteAudit\Check\Abstract\getLabel().
   */
  public function getLabel() {
    return dt('Drupalgeddon roles');
  }

  /**
   * Implements \SiteAudit\Check\Abstract\getDescription().
   */
  public function getDescription() {
    return dt('Check for known Drupalgeddon roles in the role table.');
  }

  /**
   * Implements \SiteAudit\Check\Abstract\getResultFail().
   */
  public function getResultFail() {
    $role_list = array();
    foreach ($this->registry['drupalgeddon_roles'] as $uid => $name) {
      $role_list[] = '#' . $uid . ': ' . $name;
    }
    return dt('The following roles have been detected: @drupalgeddon_roles', array(
      '@drupalgeddon_roles' => implode(', ', $role_list),
    ));
  }

  /**
   * Implements \SiteAudit\Check\Abstract\getResultInfo().
   */
  public function getResultInfo() {}

  /**
   * Implements \SiteAudit\Check\Abstract\getResultPass().
   */
  public function getResultPass() {
    return dt('No known Drupalgeddon roles were detected.');
  }

  /**
   * Implements \SiteAudit\Check\Abstract\getResultWarn().
   */
  public function getResultWarn() {}

  /**
   * Implements \SiteAudit\Check\Abstract\getAction().
   */
  public function getAction() {
    if ($this->score == SiteAuditCheckAbstract::AUDIT_CHECK_SCORE_FAIL) {
      return dt('Delete the offending roles from your site and check for other malicious activity.');
    }
  }

  /**
   * Implements \SiteAudit\Check\Abstract\calculateScore().
   */
  public function calculateScore() {
    require_once DRUPALGEDDON_BASE_PATH . '/checks/bad_roles_check.inc';
    $this->registry['drupalgeddon_roles'] = bad_roles_check_query();
    if (count($this->registry['drupalgeddon_roles']) > 0) {
      return SiteAuditCheckAbstract::AUDIT_CHECK_SCORE_FAIL;
    }
    return SiteAuditCheckAbstract::AUDIT_CHECK_SCORE_PASS;
  }
}

class SiteAuditCheckSecurityDrupalgeddonSuspiciousFiles extends SiteAuditCheckAbstract {
  /**
   * Implements \SiteAudit\Check\Abstract\getLabel().
   */
  public function getLabel() {
    return dt('Drupalgeddon suspicious files');
  }

  /**
   * Implements \SiteAudit\Check\Abstract\getDescription().
   */
  public function getDescription() {
    return dt('Check for suspicious files in the Drupal codebase.');
  }

  /**
   * Implements \SiteAudit\Check\Abstract\getResultFail().
   */
  public function getResultFail() {
    $suspicious_files_list = array();
    foreach ($this->registry['drupalgeddon_suspicious_files'] as $uid => $name) {
      $suspicious_files_list[] = '#' . $uid . ': ' . $name;
    }
    return dt('The following files have been detected: @drupalgeddon_suspicious_files', array(
      '@drupalgeddon_suspicious_files' => implode(', ', $suspicious_files_list),
    ));
  }

  /**
   * Implements \SiteAudit\Check\Abstract\getResultInfo().
   */
  public function getResultInfo() {}

  /**
   * Implements \SiteAudit\Check\Abstract\getResultPass().
   */
  public function getResultPass() {
    return dt('No suspicious files were detected.');
  }

  /**
   * Implements \SiteAudit\Check\Abstract\getResultWarn().
   */
  public function getResultWarn() {}

  /**
   * Implements \SiteAudit\Check\Abstract\getAction().
   */
  public function getAction() {
    if ($this->score == SiteAuditCheckAbstract::AUDIT_CHECK_SCORE_FAIL) {
      return dt('Delete the offending files from your site and check for other malicious activity.');
    }
  }

  /**
   * Implements \SiteAudit\Check\Abstract\calculateScore().
   */
  public function calculateScore() {
    require_once DRUPALGEDDON_BASE_PATH . '/checks/suspicious_files_check.inc';
    $this->registry['drupalgeddon_suspicious_files'] = suspicious_files_check_query();
    if (count($this->registry['drupalgeddon_suspicious_files']) > 0) {
      return SiteAuditCheckAbstract::AUDIT_CHECK_SCORE_FAIL;
    }
    return SiteAuditCheckAbstract::AUDIT_CHECK_SCORE_PASS;
  }
}
