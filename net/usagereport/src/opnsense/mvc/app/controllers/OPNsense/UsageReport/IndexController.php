<?php

/*
 * Device usage report page (Reporting > Device Usage).
 * Part of the os-usagereport plugin.
 */

namespace OPNsense\UsageReport;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/UsageReport/index');
    }
}
