{#
 # Device usage report: per-device internet download/upload between two dates.
 # Data: Insight NetFlow + Kea/Hostwatch device mapping via /usr/local/bin/usage-report.
 #}

<script>
    $( document ).ready(function() {
        let lastData = null;

        function iso(d) { return d.toISOString().slice(0, 10); }
        function setRange(from, to) {
            $("#date_from").val(iso(from));
            $("#date_to").val(iso(to));
        }
        function fmt(v) { return (v === undefined || v === null) ? '' : Number(v).toFixed(2); }
        function esc(s) { return $('<div>').text(s === undefined || s === null ? '' : String(s)).html(); }

        // quick ranges
        $("#rng_today").click(function(){ let t = new Date(); setRange(t, t); run(); });
        $("#rng_7").click(function(){ let t = new Date(); let f = new Date(); f.setDate(t.getDate() - 6); setRange(f, t); run(); });
        $("#rng_30").click(function(){ let t = new Date(); let f = new Date(); f.setDate(t.getDate() - 29); setRange(f, t); run(); });
        $("#rng_month").click(function(){ let t = new Date(); let f = new Date(t.getFullYear(), t.getMonth(), 1); setRange(f, t); run(); });
        $("#rng_lastmonth").click(function(){
            let t = new Date(); let f = new Date(t.getFullYear(), t.getMonth() - 1, 1); let l = new Date(t.getFullYear(), t.getMonth(), 0);
            setRange(f, l); run();
        });

        function render(data) {
            lastData = data;
            let showDays = $("#show_days").is(':checked');
            let rows = [];
            data.devices.forEach(function(d) {
                let name = esc(d.name) + (d.exact ? '' : ' <small class="text-muted">(approx.)</small>');
                rows.push('<tr class="device-row">' +
                    '<td>' + name + '</td>' +
                    '<td><code>' + esc(d.mac || '-') + '</code></td>' +
                    '<td>' + esc(d.ips.join(', ')) + '</td>' +
                    '<td class="text-right">' + fmt(d.download_gb) + '</td>' +
                    '<td class="text-right">' + fmt(d.upload_gb) + '</td>' +
                    '<td class="text-right"><strong>' + fmt(d.total_gb) + '</strong></td>' +
                    '</tr>');
                if (showDays) {
                    Object.keys(d.days).sort().forEach(function(day) {
                        let v = d.days[day];
                        rows.push('<tr class="day-row text-muted"><td style="padding-left:2em">' + esc(day) + '</td><td></td><td></td>' +
                            '<td class="text-right">' + fmt(v.download_gb) + '</td>' +
                            '<td class="text-right">' + fmt(v.upload_gb) + '</td>' +
                            '<td class="text-right">' + fmt(v.total_gb) + '</td></tr>');
                    });
                }
            });
            if (rows.length === 0) {
                rows.push('<tr><td colspan="6" class="text-center text-muted">{{ lang._('No traffic recorded for this range') }}</td></tr>');
            }
            $("#usage_table > tbody").html(rows.join(''));
            $("#tot_down").text(fmt(data.totals.download_gb));
            $("#tot_up").text(fmt(data.totals.upload_gb));
            $("#tot_total").text(fmt(data.totals.total_gb));
            $("#wan_down").text(fmt(data.wan.download_gb));
            $("#wan_up").text(fmt(data.wan.upload_gb));
            $("#wan_total").text(fmt(data.wan.total_gb));
            $("#range_label").text(data.date_from + ' → ' + data.date_to);
            $("#notes").html(data.notes.map(function(n){ return '<li>' + esc(n) + '</li>'; }).join(''));
            $("#results").show();
        }

        function run() {
            let from = $("#date_from").val(), to = $("#date_to").val();
            if (!from || !to) { return; }
            $("#run_btn").prop('disabled', true).find('.fa').addClass('fa-spin');
            ajaxGet('/api/usagereport/report/data', {date_from: from, date_to: to}, function(data, status) {
                $("#run_btn").prop('disabled', false).find('.fa').removeClass('fa-spin');
                if (status !== 'success' || !data || data.status !== 'ok') {
                    BootstrapDialog.show({
                        type: BootstrapDialog.TYPE_DANGER,
                        title: "{{ lang._('Report failed') }}",
                        message: esc(data && data.message ? data.message : status),
                        buttons: [{label: "{{ lang._('Close') }}", action: function(dlg){ dlg.close(); }}]
                    });
                    return;
                }
                render(data);
            });
        }

        $("#run_btn").click(run);
        $("#show_days").change(function(){ if (lastData) { render(lastData); } });

        $("#csv_btn").click(function(){
            if (!lastData) { return; }
            let lines = [['device', 'mac', 'ips', 'download_gb', 'upload_gb', 'total_gb']];
            let byDay = $("#show_days").is(':checked');
            if (byDay) { lines = [['day', 'device', 'mac', 'ips', 'download_gb', 'upload_gb', 'total_gb']]; }
            lastData.devices.forEach(function(d) {
                if (byDay) {
                    Object.keys(d.days).sort().forEach(function(day) {
                        let v = d.days[day];
                        lines.push([day, d.name, d.mac, d.ips.join(' '), v.download_gb, v.upload_gb, v.total_gb]);
                    });
                } else {
                    lines.push([d.name, d.mac, d.ips.join(' '), d.download_gb, d.upload_gb, d.total_gb]);
                }
            });
            let csv = lines.map(function(r){ return r.map(function(c){ return '"' + String(c).replace(/"/g, '""') + '"'; }).join(','); }).join('\n');
            let blob = new Blob([csv], {type: 'text/csv;charset=utf-8;'});
            let a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'device-usage_' + lastData.date_from + '_' + lastData.date_to + '.csv';
            document.body.appendChild(a); a.click(); document.body.removeChild(a);
        });

        // default: last 7 days
        $("#rng_7").click();
    });
</script>

<div class="content-box">
    <div class="content-box-main">
        <div class="table-responsive">
            <form class="form-inline" onsubmit="return false;">
                <div class="form-group" style="margin-right:1em">
                    <label for="date_from">{{ lang._('From') }}</label>
                    <input type="date" class="form-control" id="date_from">
                </div>
                <div class="form-group" style="margin-right:1em">
                    <label for="date_to">{{ lang._('To') }}</label>
                    <input type="date" class="form-control" id="date_to">
                </div>
                <button id="run_btn" type="button" class="btn btn-primary">
                    <span class="fa fa-refresh"></span> {{ lang._('Run report') }}
                </button>
                <div class="btn-group" style="margin-left:1em">
                    <button id="rng_today" type="button" class="btn btn-default">{{ lang._('Today') }}</button>
                    <button id="rng_7" type="button" class="btn btn-default">{{ lang._('7 days') }}</button>
                    <button id="rng_30" type="button" class="btn btn-default">{{ lang._('30 days') }}</button>
                    <button id="rng_month" type="button" class="btn btn-default">{{ lang._('This month') }}</button>
                    <button id="rng_lastmonth" type="button" class="btn btn-default">{{ lang._('Last month') }}</button>
                </div>
            </form>
            <hr/>
            <div id="results" style="display:none">
                <div class="form-inline" style="margin-bottom:0.5em">
                    <strong>{{ lang._('Range') }}:</strong> <span id="range_label"></span>
                    <label class="checkbox-inline" style="margin-left:2em"><input type="checkbox" id="show_days"> {{ lang._('Show per day') }}</label>
                    <button id="csv_btn" type="button" class="btn btn-default btn-xs pull-right"><span class="fa fa-download"></span> {{ lang._('Download CSV') }}</button>
                </div>
                <table class="table table-condensed table-hover" id="usage_table">
                    <thead>
                        <tr>
                            <th>{{ lang._('Device') }}</th>
                            <th>{{ lang._('MAC') }}</th>
                            <th>{{ lang._('IP address(es)') }}</th>
                            <th class="text-right">{{ lang._('Download GB') }}</th>
                            <th class="text-right">{{ lang._('Upload GB') }}</th>
                            <th class="text-right">{{ lang._('Total GB') }}</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                    <tfoot>
                        <tr>
                            <th colspan="3">{{ lang._('All devices') }}</th>
                            <th class="text-right" id="tot_down"></th>
                            <th class="text-right" id="tot_up"></th>
                            <th class="text-right" id="tot_total"></th>
                        </tr>
                        <tr class="text-muted">
                            <td colspan="3">{{ lang._('WAN total for cross-check') }}</td>
                            <td class="text-right" id="wan_down"></td>
                            <td class="text-right" id="wan_up"></td>
                            <td class="text-right" id="wan_total"></td>
                        </tr>
                    </tfoot>
                </table>
                <ul class="text-muted small" id="notes"></ul>
            </div>
        </div>
    </div>
</div>
