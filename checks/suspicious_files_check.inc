<?php

/**
 * A check for bad files.
 * https://www.drupal.org/node/2360269
 *
 * WTF people. Why can your webserver even write to your codebase?
 */
function suspicious_files_check() {
  $result = suspicious_files_check_query();
  $res = array();
  if (!empty($result)) {
    foreach ($result as $file) {
      $res[] = t('Suspicious file "@file" discovered.', array(
        '@file' => $file,
      ));
    }
  }
  if (!empty($res)) {
    return $res;
  }
}

function suspicious_files_check_query() {
  $found_files = file_scan_directory('.', '#.*\.php#', array('callback' => '_suspicious_files_callback_sites'));
  // glob(DRUPAL_ROOT . '/*/*/*.php');
  foreach ($found_files as $found_file) {
    if (!preg_match('#/sites/#', $found_file->uri)) {
      $files[] = realpath(DRUPAL_ROOT . DIRECTORY_SEPARATOR . $found_file->uri);
    }
  }

  $known_files = _suspicious_files_whitelist();
  foreach ($files as $file) {
    if (!in_array($file, $known_files)) {
      // Don't report on files in sites/* tree ... will trigger too
      // many false positives.
      if (stristr($file, '/sites/') === FALSE) {
        $return[] = $file;
      }
    }
  }
  if (!empty($return)) {
    return $return;
  }
}

/**
 * List of files in a clean Drupal 7.32 install.
 */
function _suspicious_files_whitelist() {
  $tree_list_url = 'https://github.com/drupal/drupal/tree-list/4786cb98b9db1b0727a441c4aa7b6d47670f1afe';
  if ($response = drupal_http_request($tree_list_url)) {
    if ($json = json_decode($response->data)) {
      foreach ($json->paths as $path) {
        $paths[] = realpath(DRUPAL_ROOT . '/' . $path);
      }
      return $paths;
    }
  }
}

/**
 * Callback to exclude sites/*.
 */
function _suspicious_files_callback_sites($file) {
  if (!preg_match('#./sites#', $file)) {
    return $file;
  }
}