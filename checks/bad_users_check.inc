<?php

/**
 * A check for bad users.
 * https://gist.github.com/joshkoenig/dbb543c02198330cbf87
 */
function bad_users_check() {
  $result = bad_users_check_query();
  $res = array();
  if (!empty($result)) {
    foreach ($result as $name) {
      $res[] = t('User "@name" discovered.', array(
        '@name' => $name,
      ));
    }
  }
  if (!empty($res)) {
    return $res;
  }
}

function bad_users_check_query() {
  $users = array(
    '67890',
    'admin2',
    'adminl',
    'adminstr',
    'assass',
    'configure',
    'drplsys',
    'Drupal_Reserve',
    'drupaldev',
    'jhuang',
    'malamut',
    'n0n0x',
    'ololo1',
    'owned',
    'phantom',
    'service',
    'service@drupal.org',
    'system',
    'test1',
    'tst123',
  );
  $result = db_query('SELECT uid, name FROM {users} WHERE name IN (:users)', array(
    ':users' => $users,
  ));
  $ret_val = array();
  while ($user = $result->fetchObject()) {
    $ret_val[$user->uid] = $user->name;
  }
  return $ret_val;
}
