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
    if (!preg_match('#/(sites|profiles)/#', $found_file->uri)) {
      $files[] = realpath(DRUPAL_ROOT . DIRECTORY_SEPARATOR . $found_file->uri);
    }
  }

  $known_files = _suspicious_files_whitelist();
  foreach ($files as $file) {
    if (is_array($known_files) && !in_array($file, $known_files)) {
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

  $extra_whitelist = array(
    // filename => array of valid sha1 hashes.
    'modules/help/help.api.php' => array( // A file removed with Drupal 7.29
      '6fab6bbb415ff429cfd5575820907a3fbb7d01ad', // 7.12
      '187eff591132ab334159402a273d7d174823b197', // 7.2
      'a73b016eff898e85ecd67663f2e735d9580e4cf8', // 7.0
    ),
  );
  if ($response = drupal_http_request($tree_list_url)) {
    if ($json = json_decode($response->data)) {
      foreach ($json->paths as $path) {
        $paths[] = realpath(DRUPAL_ROOT . '/' . $path);
      }

      foreach ($extra_whitelist as $path => $sha1sums) {
        $full_path = realpath(DRUPAL_ROOT . '/' . $path);
        if (in_array(sha1_file($full_path), $sha1sums)) {
          $paths[] = $full_path;
        }
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
