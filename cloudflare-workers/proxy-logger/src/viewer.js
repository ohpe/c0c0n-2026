export default {
	async fetch(request, env, ctx) {
		const template = `<!DOCTYPE html>
		<html>
		<head>
		<link rel="stylesheet" href="https://cdn.datatables.net/1.11.2/css/jquery.dataTables.min.css">
		<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
		<link rel="stylesheet" href="https://cdn.datatables.net/1.11.2/css/dataTables.bootstrap.min.css">
		<script src="https://code.jquery.com/jquery-3.6.0.js" integrity="sha256-H+K7U5CnXl1h5ywQfKtSj8PCmoN9aaq30gDh27Xc0jk=" crossorigin="anonymous"></script>
		<script src="https://cdn.datatables.net/1.11.2/js/jquery.dataTables.min.js"></script>
		<script src="https://cdn.datatables.net/1.11.2/js/dataTables.bootstrap.min.js"></script>
		</head>
		<body>
		<button onclick="deleteLogs()">Delete all logs</button>
		<style>
		  .table.dataTable  {
			font-family: Verdana, Geneva, Tahoma, sans-serif;
			font-size: 11px;
		}
		</style>
		<script>
		function deleteLogs() {
			fetch('delete-logs', { method: 'POST' })
			.then(response => {
				if (response.ok) {
					location.reload();
				}
			});
		}
		$(document).ready( function () {
			$('#dataTable').DataTable( {
		  paging: false,
		  order: [[ 0, "desc" ]],
		  buttons: [
				'copy'
			],
		  columnDefs: [
			{
				className: 'dt-body-left',
				targets: [3,4],
				render: function ( data, type, row ) {
					return data.substr( 0, 800 );
				}
			},
		  ],
		  } );
		} );
		</script>
		<table id="dataTable" class="table display">
			<thead>
				<tr>
					<th>Timestamp</th>
					<th>IP</th>
					<th>Request</th>
					<th>Response</th>
					<th>CF Headers</th>
				</tr>
			</thead>
			<tbody>`

		// set username and password for basic auth
		const username = env.USERNAME;
		const password = env.PASSWORD;

		// get the Authorization header
		const authHeader = request.headers.get('Authorization');

		// check if the Authorization header is present and has the correct value
		if (!authHeader || authHeader !== `Basic ${btoa(`${username}:${password}`)}`) {
			// if not, return a 401 Unauthorized response
			return new Response('Unauthorized', { status: 401, headers: { 'WWW-Authenticate': 'Basic realm="Restricted"' } });
		}

		// parse the request URL
		const url = new URL(request.url);

		// check if the request method is POST
		if (request.method === 'POST' && url.pathname === env.LOGGER_PATH + 'delete-logs') {
			// fetch all logs from KV namespace
			const logs = await env.LOGS.list();
			// delete all logs
			await Promise.all(logs.keys.map((log) => env.LOGS.delete(log.name)));
			// return a 200 OK response
			return new Response('', { status: 200 });
		}
		
		// try read json from request body
		let json;
		try {
			// read logs from KV namespace. timestammp is the key
			const logs = await env.LOGS.list();
			// sort logs by timestamp
			logs.keys.sort((a, b) => parseInt(b.name) - parseInt(a.name));
			// get the log entries and add timestamps to the array.
			// A key may be deleted between list() and get() (for example right
			// after the "Delete all logs" button), in which case get() returns
			// null: skip those entries instead of crashing.
			const entries = (await Promise.all(logs.keys.map(async (log) => {
				const value = await env.LOGS.get(log.name);
				if (value === null) return null;
				return JSON.stringify({ ...JSON.parse(value), timestamp: log.name });
			}))).filter(Boolean);
			
			// create an array of table rows
			const tableRows = entries.map((entry) => {
				const { timestamp, ip, request, response, cf } = JSON.parse(entry);
				let cfHtml = JSON.stringify(cf, null, 2).replace(/\n/g, '<br>');

				//html encode request and response
				let requestHtml = request.replace(/</g, '&lt;').replace(/>/g, '&gt;');
				let responseHtml = response.replace(/</g, '&lt;').replace(/>/g, '&gt;');
				requestHtml = requestHtml.replace(/\r\n/g, '<br>').replace(/\n/g, '<br>');
				responseHtml = responseHtml.replace(/\r\n/g, '<br>').replace(/\n/g, '<br>');

				// wrap each entry in a table row so that the table fits the screen
				return `<tr>
					<td>${new Date(parseInt(timestamp)).toISOString()}</td>
					<td>${ip}</td>
					<td><pre>${requestHtml}</td>
					<td>${responseHtml}</td>
					<td>${cfHtml}</td>
				</tr>`;
				
			});
			
			
			// create the HTML response
			const html = `${template}${tableRows.join('')}</tbody></table></body></html>`;
			// return a 200 OK response
			return new Response(html, { headers: { 'Content-Type': 'text/html' } });
		} catch (e) {
			// if it fails, return a 400 Bad Request response
			console.error(e);
			return new Response('', { status: 400 });
		}
	},
};
