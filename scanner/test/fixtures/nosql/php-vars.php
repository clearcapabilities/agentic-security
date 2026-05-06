<?php
// PHP variables named after MongoDB operators — should NOT trigger NoSQL Injection
$where = "test";
$type = $_GET['t'];
$gt = 100;
echo $where . $type . $gt;

function findAll() {
  $or = ['a', 'b'];
  return $or;
}
