<?php

/**
 * A check for bad files.
 * https://www.drupal.org/node/2360269
 *
 * WTF people. Why can your website even write to your codebase?
 */
function suspicious_files_check() {
  $php_files = glob(DRUPAL_ROOT . '/*/*/*.php');

  $known_files = _suspicious_files_whitelist();
  foreach ($php_files as $php_file) {
    $file = basename($php_file);
    if (!in_array($php_file, $known_files)) {
      // Don't report on files in sites/* tree ... will trigger too
      // many false positives.
      if (stristr($php_file, '/sites/') === FALSE) {
        $return[] = t('Unrecognised PHP file @file discovered.', array('@file' => $php_file));
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