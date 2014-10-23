<?php

/**
 * https://gist.github.com/joshkoenig/a941d1fd58c3383b7eb7
 * Check for bad roles!
 */
function bad_roles_check() {
  $res = array();
  $result = bad_roles_check_query();
  if (!empty($result)) {
    foreach ($result as $name) {
      $res[] = t('Role "@name" discovered.', array(
        '@name' => $name,
      ));
    }
  }
  if (!empty($res)) {
    return $res;
  }
}

function bad_roles_check_query() {
  $roles = array(
    'megauser',
  );
  $result = db_query('SELECT rid, name FROM {role} WHERE name IN (:roles)', array(
    ':roles' => $roles,
  ));
  while ($role = $result->fetchObject()) {
    $ret_val[$role->rid] = $role->name;
  }
  return $ret_val;
}
