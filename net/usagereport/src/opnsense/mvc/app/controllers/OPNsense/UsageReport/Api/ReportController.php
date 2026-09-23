<?php

/*
 * API for the device usage report: /api/usagereport/report/data?date_from=YYYY-MM-DD&date_to=YYYY-MM-DD
 * Runs usage-report.py --json through configd (action "usagereport report").
 */

namespace OPNsense\UsageReport\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ReportController extends ApiControllerBase
{
    private function validDate($value)
    {
        if (!is_string($value) || !preg_match('/^\d{4}-\d{2}-\d{2}$/', $value)) {
            return false;
        }
        $parts = explode('-', $value);
        return checkdate((int)$parts[1], (int)$parts[2], (int)$parts[0]);
    }

    public function dataAction()
    {
        $date_from = $this->request->get('date_from');
        $date_to = $this->request->get('date_to');
        if (!$this->validDate($date_from) || !$this->validDate($date_to)) {
            return ['status' => 'error', 'message' => 'Dates must be YYYY-MM-DD'];
        }
        if ($date_from > $date_to) {
            [$date_from, $date_to] = [$date_to, $date_from];
        }
        $backend = new Backend();
        $raw = $backend->configdpRun('usagereport report', [$date_from, $date_to]);
        $data = json_decode((string)$raw, true);
        if (!is_array($data)) {
            return ['status' => 'error', 'message' => 'Report failed: ' . trim((string)$raw)];
        }
        $data['status'] = 'ok';
        return $data;
    }
}
