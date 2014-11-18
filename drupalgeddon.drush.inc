<?php
/**
 * @file
 * Drush command check for known Drupalgeddon exploits.
 */

define('DRUPALGEDDON_BASE_PATH', __DIR__);

/**
 * Implements hook_drush_help().
 */
function drupalgeddon_drush_help($section) {
  switch ($section) {
    case 'drush:drupalgeddon':
      return dt('Run all Drupalgeddon checks.');
  }
}

/**
 * Implements hook_drush_command().
 */
function drupalgeddon_drush_command() {
  $items = array();

  $items['drupalgeddon-test'] = array(
    'description' => 'Check for known indications of Drupalgeddon exploit.',
    'callback' => 'drush_drupalgeddon',
    'options' => array(
      'whitelist-files' => 'Files to whitelist from the suspicious files check. Separate multiple files with a comma.',
      'whitelist-hashes' => 'Specify a file that contains a list of files and sha1 hashes to whitelist from the suspicious files check. The file format uses .info file syntax: files[foo.php] = 4a6c61176c77dcbea06d1458d7050b1e8db3ce91.',
    ),
    'examples' => array(
      'drush drugtest' => 'Scan the sites for known indications of Drupalgeddon attacks.',
    ),
    'aliases' => array('drugtest'),
  );

  return $items;
}

/**
 * Scan for known Drupalgeddon attacks.
 */
function drush_drupalgeddon() {
  $results = array();

  if (version_compare(VERSION, '7.0', '<') || version_compare(VERSION, '8.0', '>=')) {
    drush_log('Site is not Drupal 7.', 'ok');
    return;
  }
  else {
    if ($checks = glob(dirname(__FILE__) . '/checks/*_check.inc')) {
      foreach ($checks as $check) {
        include_once $check;
        $info = pathinfo($check);
        if (function_exists($info['filename'])) {
          $check = $info['filename']();
          if (!empty($check)) {
            $results = array_merge($check, $results);
          }
        }
      }
    }
  }

  if (!empty($results)) {
    drush_log('Site tested positive for known Drupalgeddon exploit checks', 'error');
    foreach ($results as $result) {
      drush_log($result, 'error');
    }
  }
  else {
    drush_log('No evidence of known Drupalgeddon exploits found.', 'ok');
  }
}

/**
 * Implements hook_drush_command_alter().
 */
function drupalgeddon_drush_command_alter(&$command) {
  // Add Drupalgeddon checks to existing security report.
  if ($command['command'] == 'audit_security') {
    $security_review_checks = array(
      'DrupalgeddonUsers',
      'DrupalgeddonRoles',
      'DrupalgeddonUserConcurrency',
      'DrupalgeddonSuspiciousFiles',
    );
    foreach ($security_review_checks as $name) {
      $command['checks'][] = array(
        'name' => $name,
        'location' => __DIR__ . '/drupalgeddon.site_audit.inc',
      );
    }
  }
}
