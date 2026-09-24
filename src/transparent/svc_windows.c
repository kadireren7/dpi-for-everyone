#include "tp_sys.h"

#include <windows.h>
#include <string.h>

/* ============================================================
 * `dpi-proxy.exe --mode transparent --service`: the same server as a
 * native Windows service ("dpi-proxy", created by
 * scripts/windows/install.ps1). Stop/shutdown requests from the
 * service control manager ask the server to stop; it removes its
 * interception and returns, and the service reports STOPPED.
 * ============================================================ */

#define SVC_NAME "dpi-proxy"

static SERVICE_STATUS_HANDLE	g_handle;
static SERVICE_STATUS			g_status;
static t_tp_options				g_opt;
static int						g_rc;

static void	report(DWORD state, DWORD exit_code, DWORD wait_hint)
{
	g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	g_status.dwCurrentState = state;
	g_status.dwWin32ExitCode = exit_code;
	g_status.dwWaitHint = wait_hint;
	g_status.dwControlsAccepted = (state == SERVICE_RUNNING)
		? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
	if (state == SERVICE_RUNNING || state == SERVICE_STOPPED)
		g_status.dwCheckPoint = 0;
	else
		g_status.dwCheckPoint++;
	SetServiceStatus(g_handle, &g_status);
}

static DWORD WINAPI	control(DWORD code, DWORD type, LPVOID data, LPVOID ctx)
{
	(void)type;
	(void)data;
	(void)ctx;
	if (code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN)
	{
		report(SERVICE_STOP_PENDING, NO_ERROR, 10000);
		tp_request_stop();
		return (NO_ERROR);
	}
	if (code == SERVICE_CONTROL_INTERROGATE)
		return (NO_ERROR);
	return (ERROR_CALL_NOT_IMPLEMENTED);
}

static void WINAPI	service_main(DWORD argc, LPSTR *argv)
{
	(void)argc;
	(void)argv;
	g_handle = RegisterServiceCtrlHandlerExA(SVC_NAME, control, NULL);
	if (g_handle == NULL)
		return ;
	memset(&g_status, 0, sizeof(g_status));
	report(SERVICE_START_PENDING, NO_ERROR, 10000);
	report(SERVICE_RUNNING, NO_ERROR, 0);
	g_rc = run_transparent_server(&g_opt);
	/* a failed start ends in an error exit code, which lets the
	 * service's recovery settings restart it */
	report(SERVICE_STOPPED, g_rc == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR,
		0);
}

int	tp_windows_service_run(const t_tp_options *opt)
{
	SERVICE_TABLE_ENTRYA	table[2];

	g_opt = *opt;
	memset(table, 0, sizeof(table));
	table[0].lpServiceName = (LPSTR)SVC_NAME;
	table[0].lpServiceProc = service_main;
	if (!StartServiceCtrlDispatcherA(table))
		return (-1);
	return (g_rc);
}
