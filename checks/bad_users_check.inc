<?php
/**
 * @file
 * Check for users with known malicious names.
 */

/**
 * A check for bad users.
 * @link https://gist.github.com/joshkoenig/dbb543c02198330cbf87
 */
function bad_users_check() {
  $result = bad_users_check_for_names();
  $res = array();
  if (!empty($result)) {
    foreach ($result as $name) {
      $res[] = t('User "@name" discovered.', array(
        '@name' => $name,
      ));
    }
  }

  // Find any reported problems with the order of the users table
  $res = array_merge($res, bad_users_check_order());
  // Find any reported problems with nonexistent users assigned to roles
  $res = array_merge($res, bad_users_check_user_roles());
  return $res;
}

/**
 * Gather data for bad users check.
 *
 * @return array
 *   User names keyed by user ids.
 */
function bad_users_check_for_names() {
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
    'Kkk1123',
    'wc846',
    'drupalsys',
    'us1_admin',
    'us2_admin',
    'snyder_rachel_810',
    'rice_hannah_788',
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

/**
 * Helper function to display [username] ([uid]) for a given user
 */
function bad_users_get_name($user) {
  return $user->name . ' (' . $user->uid . ')';
}

/**
 * Check for any ordering issues in the users table, such as uid gaps or
 * users being created before those that have a lower uid.
 * @link https://www.drupal.org/node/2368763
 */
function bad_users_check_order() {
  $result = db_query('SELECT uid, created, name FROM {users} ORDER BY uid ASC');
  $report = array();

  $last_user = NULL;
  while ($user = $result->fetchObject()) {
    if ($last_user === NULL) {
      // Check if the first user listed is anonymous. This may indicate a
      // problem with the user table
      if ($user->uid !== '0') {
        if ((int)$user->uid < 0) {
          $report[] = 'There is a user with a uid less than zero';
        }
        else {
          $report[] = 'There is no anonymous user account';
        }
      }

      // Since this is the first user, we have nothing to compare against.
      $last_user = $user;
      continue;
    }

    // If we have a previous user, compare the current user's data against it
    // and ensure everything appears to be sequential.

    // Check the gap in uids between users and warn if it is greater than 50
    $uid_gap = ((int)$user->uid - (int)$last_user->uid);
    if ($uid_gap >= 50) {
      $report[] = 'Warning: User ' . bad_users_get_name($user) . ' has a uid ' .
        'that is ' . $uid_gap . ' higher than ' . bad_users_get_name($last_user);
    }

    // Check whether this timestamp falls after the previous user
    if ((int)$user->created < (int)$last_user->created) {
      $report[] = 'User ' . bad_users_get_name($user) . ' has a ' .
        'created timestamp before ' . bad_users_get_name($last_user);
    }

    // Set the $last_user to the user we just processed
    $last_user = $user;
  }

  return $report;
}

/**
 * Check for any nonexistent (deleted?) users assigned to roles
 * @link https://www.drupal.org/node/2368763
 */
function bad_users_check_user_roles() {
  $report = array();

  $sql = <<<sql
SELECT ur.uid, ur.rid
FROM {users_roles} ur
LEFT JOIN {users} u ON u.uid = ur.uid
WHERE u.uid IS NULL
sql;
  $result = db_query($sql);

  $role_cache = array();

  while ($user_role = $result->fetchObject()) {
    if (isset($role_cache[$user_role->rid]) === FALSE) {
      $role = user_role_load($user_role->rid);
      if ($role !== FALSE) {
        $role_cache[$user_role->rid] = $role->name . ' (' . $role->rid . ')';
      }
      else {
        $role_cache[$user_role->rid] = '[nonexistent] #' . $user_role->rid;
      }
    }
    $report[] = 'Nonexistent user #' . $user_role->uid . ' is assigned to ' .
      'role ' . $role_cache[$user_role->rid];
  }

  return $report;
}
