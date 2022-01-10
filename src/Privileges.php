<?php
namespace booosta\privileges;
use \booosta\Framework as b;
b::init_module('privileges');

class Privileges extends \booosta\base\Module
{
  use moduletrait_privileges;

  public function check_role_loops($role, $toprole = null)
  {
    if($role == $toprole) return false;
    if($toprole === null) $toprole = $role;

    $subroles = $this->get_subroles($role);
    foreach($subroles as $subrole)
      if($this->check_role_loops($subrole, $toprole) === false) return false;

    return true;
  }

  protected function get_subroles($role_id) { return []; }
}
