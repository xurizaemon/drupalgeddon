<?php
/**
 * @file
 * Provide Drush command to check for Drupalgeddon exploits seen in
 * the wild.
 */

/**
 * Implements hook_drush_help().
 */
function drupalgeddon_drush_help($section) {
  switch ($section) {
    case 'drush:drupalgeddon':
      return dt('Run a series of Drupalgeddon checks.');
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
    ),
    'examples' => array(
      'drush drugged-test' => 'Scan the sites for known indications of Drupalgeddon attacks.',
    ),
    'aliases' => array('drugtest'),
  );

  return $items;
}

/**
 * Scan for known Drupalgeddon attacks.
 */
function drush_drupalgeddon() {
  $drupalgeddon_test_positive = FALSE;

  if (version_compare(VERSION, '7.0', '>=') && version_compare(VERSION, '8.0', '<=')) {
    // https://gist.github.com/joshkoenig/dbb543c02198330cbf87
    // Check for a user named 'configure'
    $bad_users = array(
      'configure',
      'system',
      'n0n0x',
    );
    foreach ($bad_users as $bad_user) {
      if ($result = db_query('SELECT n.uid FROM {users} n WHERE n.name = :name', array(':name' => $bad_user))) {
        if ($user = $result->fetchObject()) {
          $drupalgeddon_test_positive = TRUE;
          drush_log(t('User @name discovered.', array('@name' => $bad_user)), 'error');
        }
      }
    }

    // https://gist.github.com/joshkoenig/70ebb6af239dd95f3ce6
    // Check for menu_router attacks with malicious callbacks
    $bad_callbacks = array(
      'assert',
      'file_put_contents',
      'eval'
    );
    foreach ($bad_callbacks as $bad_callback) {
      if ($result = db_query('SELECT mr.path FROM {menu_router} mr WHERE mr.access_callback = :cb', array(':cb' => $bad_callback))) {
        if ($user = $result->fetchObject()) {
          $drupalgeddon_test_positive = TRUE;
          drush_log(t('Menu router @name discovered.', array('@name' => $bad_callback)), 'error');
        }
      }
    }

    // https://gist.github.com/joshkoenig/a941d1fd58c3383b7eb7
    // Check for bad roles!
    $bad_roles = array('megauser');
    foreach ($bad_roles as $bad_role) {
      if ($result = db_query('SELECT name FROM {role} r WHERE r.name = :name', array(':name' => $bad_role))) {
        if ($role = $result->fetchObject()) {
          $drupalgeddon_test_positive = TRUE;
          drush_log(t('Role @name discovered.', array('@name' => $bad_role)), 'error');
        }
      }
    }
  }
  else {
    drush_log('Site is not Drupal 7.');
  }

  if ($drupalgeddon_test_positive) {
    drush_log('Site tested positive.', 'error');
  }
  else {
    drush_log('For these known exploits, site tests clear.', 'ok');
  }
}
