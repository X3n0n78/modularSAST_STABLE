<?php
/**
 * Test file for PHP security vulnerabilities
 * This file contains intentional security issues for testing
 */

// Command injection vulnerability
$filename = $_GET['file'];
exec("cat " . $filename);

// SQL injection vulnerability
$user_id = $_POST['id'];
$query = "SELECT * FROM users WHERE id = " . $user_id;
mysql_query($query);

// XSS vulnerability
$user_name = $_GET['name'];
echo "<h1>Welcome " . $user_name . "</h1>";

// Deserialization vulnerability
$data = $_COOKIE['session'];
$session = unserialize($data);

// File inclusion vulnerability
$page = $_GET['page'];
include($page . ".php");

// Weak cryptography
$password = $_POST['password'];
$hash = md5($password);

// Safe code with suppression
$safe_input = $_GET['input'];
// nosast: eval
eval($safe_input);

?>
