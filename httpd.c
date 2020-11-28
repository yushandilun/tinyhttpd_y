/* J. David's webserver */
/* This is a simple webserver.
 * Created November 1999 by J. David Blackstone.
 * CSE 4344 (Network concepts), Prof. Zeigler
 * University of Texas at Arlington
 */
/* This program compiles for Sparc Solaris 2.6.
 * To compile for Linux:
 *  1) Comment out the #include <pthread.h> line.
 *  2) Comment out the line that defines the variable newthread.
 *  3) Comment out the two lines that run pthread_create().
 *  4) Uncomment the line that runs accept_request().
 *  5) Remove -lsocket from the Makefile.
 */
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/wait.h>
#include <stdlib.h>

#define ISspace(x) isspace((int)(x))

#define SERVER_STRING "Server: jdbhttpd/0.1.0\r\n"

void accept_request(int);
void bad_request(int);
void cat(int, FILE *);
void cannot_execute(int);
void error_die(const char *);
void execute_cgi(int, const char *, const char *, const char *);
int get_line(int, char *, int);
void headers(int, const char *);
void not_found(int);
void serve_file(int, const char *);
int startup(u_short *);
void unimplemented(int);

/**********************************************************************/
/* A request has caused a call to accept() on the server port to
 * return.  Process the request appropriately.
 * Parameters: the socket connected to the client */
/**********************************************************************/

// 线程处理函数
void accept_request(int client)
{
 char buf[1024];    // 读取行数据时的缓冲区
 int numchars;      // 读取了多少字符
 char method[255];  // 存储HTTP请求名称（字符串）
 char url[255];
 char path[512];
 size_t i, j;
 struct stat st;
 int cgi = 0;      /* becomes true if server decides this is a CGI
                    * program */
 char *query_string = NULL;

    // 一个HTTP请求报文由请求行（requestline）、请求头部（header）、空行和请求数据4个部分
    // 组成，请求行由请求方法字段（get或post）、URL字段和HTTP协议版本字段3个字段组成，它们
    // 用空格分隔。如：GET /index.html HTTP/1.1。
    // 解析请求行，把方法字段保存在method变量中。
    // 读取HTTP头第一行：GET/index.php HTTP 1.1
 numchars = get_line(client, buf, sizeof(buf));
 i = 0; j = 0;

 // 把客户端的请求方法存到method数组
 while (!ISspace(buf[j]) && (i < sizeof(method) - 1))
 {
  method[i] = buf[j];
  i++; j++;
 }
 method[i] = '\0';

 // 只能识别get和post
 if (strcasecmp(method, "GET") && strcasecmp(method, "POST"))
 {
  unimplemented(client);
  return;
 }

// POST的时候开启cgi
 if (strcasecmp(method, "POST") == 0)
  cgi = 1;

 // 解析并保存请求的URL（如有问号，也包括问号及之后的内容）
 i = 0;

 // 跳过空白字符
 while (ISspace(buf[j]) && (j < sizeof(buf)))
  j++;

 // 从缓冲区中把URL读取出来
 while (!ISspace(buf[j]) && (i < sizeof(url) - 1) && (j < sizeof(buf)))
 {

  // 存在url
  url[i] = buf[j];
  i++; j++;
 }
 // 保存URL
 url[i] = '\0';

    // 先处理如果是GET请求的情况
    // 如果是get方法，请求参数和对应的值附加在URL后面，利用一个问号（“？”）代表URL的结
    // 尾与请求参数的开始，传递参数长度受限制。如index.jsp?10023，其中10023就是要传递
    // 的参数。这段代码将参数保存在query_string中。
 if (strcasecmp(method, "GET") == 0)
 {
  // 待处理请求为url
  query_string = url;
  // 移动指针，去找GET参数，即?后面的部分
  while ((*query_string != '?') && (*query_string != '\0'))
   query_string++;
  // 如果找到了的话，说明这个请求也需要调用脚本来处理
  // 此时就把请求字符串单独抽取出来
  // GET方法特点，？后面为参数
  if (*query_string == '?')
  {
   // 开启cgi
   cgi = 1;
   // query_string指针指向的是真正的请求参数
   *query_string = '\0';
   query_string++;
  }
 }

     // 保存有效的url地址并加上请求地址的主页索引。默认的根目录是htdocs下
    // 这里是做以下路径拼接，因为url字符串以'/'开头，所以不用拼接新的分割符
    // 格式化url到path数组，html文件都早htdocs中
 sprintf(path, "htdocs%s", url);
 // 如果访问路径的最后一个字符时'/'，就为其补全，即默认访问index.html
 if (path[strlen(path) - 1] == '/')
  strcat(path, "index.html");

 // 访问请求的文件，如果文件不存在直接返回，如果存在就调用CGI程序来处理
 // 根据路径找到对应文件
 if (stat(path, &st) == -1) {
     // 如果不存在，就把剩下的请求头从缓冲区中读出去
     // 把所有headers的信息都丢弃
  while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
   numchars = get_line(client, buf, sizeof(buf));
  // 然后返回一个404错误，即回应客户端找不到
  not_found(client);
 }
 else
 {
    // 如果文件存在但却是个目录，则继续拼接路径，默认访问这个目录下的index.html
  if ((st.st_mode & S_IFMT) == S_IFDIR)
   strcat(path, "/index.html");
        // 如果文件具有可执行权限，就执行它
        // 如果需要调用CGI（CGI标志位置1）在调用CGI之前有一段是对用户权限的判断，对应
        // 含义如下：S_IXUSR：用户可以执行
        //          S_IXGRP：组可以执行
        //          S_IXOTH：其它人可以执行
  if ((st.st_mode & S_IXUSR) ||
      (st.st_mode & S_IXGRP) ||
      (st.st_mode & S_IXOTH)    )
   cgi = 1;

  // 不是cgi，直接把服务器文件返回，否则执行cgi
  if (!cgi)
   serve_file(client, path);
  else
   execute_cgi(client, path, method, query_string);
 }

 // 断开与客户端的连接（HTTP特点：无连接）
 close(client);
}

/**********************************************************************/
/* Inform the client that a request it has made has a problem.
 * Parameters: client socket */
/**********************************************************************/
void bad_request(int client)
{
 char buf[1024];

 sprintf(buf, "HTTP/1.0 400 BAD REQUEST\r\n");
 send(client, buf, sizeof(buf), 0);
 sprintf(buf, "Content-type: text/html\r\n");
 send(client, buf, sizeof(buf), 0);
 sprintf(buf, "\r\n");
 send(client, buf, sizeof(buf), 0);
 sprintf(buf, "<P>Your browser sent a bad request, ");
 send(client, buf, sizeof(buf), 0);
 sprintf(buf, "such as a POST without a Content-Length.\r\n");
 send(client, buf, sizeof(buf), 0);
}

/**********************************************************************/
/* Put the entire contents of a file out on a socket.  This function
 * is named after the UNIX "cat" command, because it might have been
 * easier just to do something like pipe, fork, and exec("cat").
 * Parameters: the client socket descriptor
 *             FILE pointer for the file to cat */
/**********************************************************************/
void cat(int client, FILE *resource)
{
 char buf[1024];

 fgets(buf, sizeof(buf), resource);
 while (!feof(resource))
 {
  send(client, buf, strlen(buf), 0);
  fgets(buf, sizeof(buf), resource);
 }
}

/**********************************************************************/
/* Inform the client that a CGI script could not be executed.
 * Parameter: the client socket descriptor. */
/**********************************************************************/
void cannot_execute(int client)
{
 char buf[1024];

 sprintf(buf, "HTTP/1.0 500 Internal Server Error\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "Content-type: text/html\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "<P>Error prohibited CGI execution.\r\n");
 send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Print out an error message with perror() (for system errors; based
 * on value of errno, which indicates system call errors) and exit the
 * program indicating an error. */
/**********************************************************************/
void error_die(const char *sc)
{
 perror(sc);
 exit(1);
}

/**********************************************************************/
/* Execute a CGI script.  Will need to set environment variables as
 * appropriate.
 * Parameters: client socket descriptor
 *             path to the CGI script */
/**********************************************************************/
#if 0
void execute_cgi(int client, const char *path,
                 const char *method, const char *query_string)
{
 char buf[1024];
 int cgi_output[2];
 int cgi_input[2];
 pid_t pid;
 int status;
 int i;
 char c;
 int numchars = 1;
 :exe "!" . g:ctags_command
     int content_length = -1;

 buf[0] = 'A'; buf[1] = '\0';
 if (strcasecmp(method, "GET") == 0)
  while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
   numchars = get_line(client, buf, sizeof(buf));
 else    /* POST */
 {
  numchars = get_line(client, buf, sizeof(buf));
  while ((numchars > 0) && strcmp("\n", buf))
  {
   buf[15] = '\0';
   if (strcasecmp(buf, "Content-Length:") == 0)
    content_length = atoi(&(buf[16]));
   numchars = get_line(client, buf, sizeof(buf));
  }
  if (content_length == -1) {
   bad_request(client);
   return;
  }
 }

 sprintf(buf, "HTTP/1.0 200 OK\r\n");
 send(client, buf, strlen(buf), 0);

 if (pipe(cgi_output) < 0) {
  cannot_execute(client);
  return;
 }
 if (pipe(cgi_input) < 0) {
  cannot_execute(client);
  return;
 }

 if ( (pid = fork()) < 0 ) {
  cannot_execute(client);
  return;
 }
 if (pid == 0)  /* child: CGI script */
 {
  char meth_env[255];
  char query_env[255];
  char length_env[255];

  dup2(cgi_output[1], 1);
  dup2(cgi_input[0], 0);
  close(cgi_output[0]);
  close(cgi_input[1]);
  sprintf(meth_env, "REQUEST_METHOD=%s", method);
  putenv(meth_env);
  if (strcasecmp(method, "GET") == 0) {
   sprintf(query_env, "QUERY_STRING=%s", query_string);
   putenv(query_env);
  }
  else {   /* POST */
   sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
   putenv(length_env);
  }
  execl(path, path, NULL);
  exit(0);
 } else {    /* parent */
  close(cgi_output[1]);
  close(cgi_input[0]);
  if (strcasecmp(method, "POST") == 0)
   for (i = 0; i < content_length; i++) {
    recv(client, &c, 1, 0);
    write(cgi_input[1], &c, 1);
   }
  while (read(cgi_output[0], &c, 1) > 0)
   send(client, &c, 1, 0);

  close(cgi_output[0]);
  close(cgi_input[1]);
  waitpid(pid, &status, 0);
 }
}
#else
void execute_cgi(int client, const char *path,
        const char *method, const char *query_string)
{
    char buf[1024];
    int cgi_output[2];
    int cgi_input[2];
    pid_t pid;
    int status;
    int i;
    char c;
    int numchars = 1;
    int content_length = -1;

    // 首先需要根据请求是Get还是Post，来分别进行处理
    buf[0] = 'A'; buf[1] = '\0';
    // 如果是Get，那么就忽略剩余的请求头
    if (strcasecmp(method, "GET") == 0)
        // 把所有的HTTP header读取并丢弃
        while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
            numchars = get_line(client, buf, sizeof(buf));
    // 如果是Post，那么就需要读出请求长度即Content-Length
    else if (strcasecmp(method, "POST") == 0) /*POST*/
    {
        // 对POST的HTTP请求中找出content_length
        numchars = get_line(client, buf, sizeof(buf));
        while ((numchars > 0) && strcmp("\n", buf))
        {
            // 使用\0进行分割
            buf[15] = '\0';
            // HTTP请求的特点
            if (strcasecmp(buf, "Content-Length:") == 0)
                content_length = atoi(&(buf[16]));
            numchars = get_line(client, buf, sizeof(buf));
        }
        // 如果请求长度不合法（比如根本就不是数字），那么就报错，即没有找到content_length
        if (content_length == -1) {
            // 错误请求
            bad_request(client);
            return;
        }
    }
    else/*HEAD or other*/
    {
    }

    // 建立管道
    if (pipe(cgi_output) < 0) {
        // 错误处理
        cannot_execute(client);
        return;
    }
    // 建立管道
    if (pipe(cgi_input) < 0) {
        // 错误处理
        cannot_execute(client);
        return;
    }

    // fork自身，生成两个进程
    if ( (pid = fork()) < 0 ) {   // 复制一个线程
        // 错误处理
        cannot_execute(client);
        return;
    }
    sprintf(buf, "HTTP/1.0 200 OK\r\n");
    send(client, buf, strlen(buf), 0);
    // 子进程要调用CGI脚本
    if (pid == 0)  /* child: CGI script */
    {
        // 环境变量缓冲区，会存在溢出风险
        char meth_env[255];
        char query_env[255];
        char length_env[255];
        // 重定向管道
        // 把父进程读写管道的描述符分别绑定到子进程的标准输入和输出
        // dup2功能与freopen()函数类似
        dup2(cgi_output[1], STDOUT);   // 把STDOUT重定向到cgi_output的写入端
        dup2(cgi_input[0], STDIN);     // 把STDIN重定向到cgi_input的读取端
        // 关闭不必要的描述符
        close(cgi_output[0]);          // 关闭cgi_inout的写入端和cgi_output的读取端
        close(cgi_input[1]);

        // 服务器设置环境变量，即request_method的环境变量
        // 设置基本的CGI环境变量，请求类型、参数、长度之类
        sprintf(meth_env, "REQUEST_METHOD=%s", method);
        putenv(meth_env);
        if (strcasecmp(method, "GET") == 0) {
            // 设置query_string的环境变量
            sprintf(query_env, "QUERY_STRING=%s", query_string);
            putenv(query_env);
        }
        else {   /* POST */
            // 设置content_length的环境变量
            sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
            putenv(length_env);
        }

        // 用execl运行cgi程序
        execl(path, NULL);
        exit(0);
    } else {    /* parent */

        // 父进程代码
        // 关闭cgi_input的读取端和cgi_output的写入端
        close(cgi_output[1]);
        close(cgi_input[0]);
        // 对于Post请求，要直接write()给子进程
        // 这样子进程所调用的脚本就可以从标准输入取得Post数据
        if (strcasecmp(method, "POST") == 0)
            // 接收POST过来的数据
            for (i = 0; i < content_length; i++) {
                recv(client, &c, 1, 0);
                // 把POST数据写入cgi_input，现在重定向到STDIN
                write(cgi_input[1], &c, 1);
            }
        // 然后父进程再从输出管道里面读出所有结果，返回给客户端
        while (read(cgi_output[0], &c, 1) > 0)
            send(client, &c, 1, 0);

        // 关闭管道
        close(cgi_output[0]);
        close(cgi_input[1]);
        // 最后等待子进程结束，即等待子进程
        waitpid(pid, &status, 0);
    }
}
#endif

/**********************************************************************/
/* Get a line from a socket, whether the line ends in a newline,
 * carriage return, or a CRLF combination.  Terminates the string read
 * with a null character.  If no newline indicator is found before the
 * end of the buffer, the string is terminated with a null.  If any of
 * the above three line terminators is read, the last character of the
 * string will be a linefeed and the string will be terminated with a
 * null character.
 * Parameters: the socket descriptor
 *             the buffer to save the data in
 *             the size of the buffer
 * Returns: the number of bytes stored (excluding null) */
/**********************************************************************/
int get_line(int sock, char *buf, int size)
{
 int i = 0;
 char c = '\0';
 int n;

 while ((i < size - 1) && (c != '\n'))
 {
  n = recv(sock, &c, 1, 0);
  /* DEBUG printf("%02X\n", c); */
  if (n > 0)
  {
   if (c == '\r')
   {
    n = recv(sock, &c, 1, MSG_PEEK);
    /* DEBUG printf("%02X\n", c); */
    if ((n > 0) && (c == '\n'))
     recv(sock, &c, 1, 0);
    else
     c = '\n';
   }
   buf[i] = c;
   i++;
  }
  else
   c = '\n';
 }
 buf[i] = '\0';
 
 return(i);
}

/**********************************************************************/
/* Return the informational HTTP headers about a file. */
/* Parameters: the socket to print the headers on
 *             the name of the file */
/**********************************************************************/
void headers(int client, const char *filename)
{
 char buf[1024];
 (void)filename;  /* could use filename to determine file type */

 strcpy(buf, "HTTP/1.0 200 OK\r\n");
 send(client, buf, strlen(buf), 0);
 strcpy(buf, SERVER_STRING);
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "Content-Type: text/html\r\n");
 send(client, buf, strlen(buf), 0);
 strcpy(buf, "\r\n");
 send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Give a client a 404 not found status message. */
/**********************************************************************/
void not_found(int client)
{
 char buf[1024];

 sprintf(buf, "HTTP/1.0 404 NOT FOUND\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, SERVER_STRING);
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "Content-Type: text/html\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "<HTML><TITLE>Not Found</TITLE>\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "<BODY><P>The server could not fulfill\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "your request because the resource specified\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "is unavailable or nonexistent.\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "</BODY></HTML>\r\n");
 send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Send a regular file to the client.  Use headers, and report
 * errors to client if they occur.
 * Parameters: a pointer to a file structure produced from the socket
 *              file descriptor
 *             the name of the file to serve */
/**********************************************************************/
void serve_file(int client, const char *filename)
{
 FILE *resource = NULL;
 int numchars = 1;
 char buf[1024];

 buf[0] = 'A'; buf[1] = '\0';
 while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
  numchars = get_line(client, buf, sizeof(buf));

 resource = fopen(filename, "r");
 if (resource == NULL)
  not_found(client);
 else
 {
  headers(client, filename);
  cat(client, resource);
 }
 fclose(resource);
}

/**********************************************************************/
/* This function starts the process of listening for web connections
 * on a specified port.  If the port is 0, then dynamically allocate a
 * port and modify the original port variable to reflect the actual
 * port.
 * Parameters: pointer to variable containing the port to connect on
 * Returns: the socket */
/**********************************************************************/
// startup函数：按照TCP连接的正常流程依次调用socket，bind，listen函数。
// 监听套接字端口既可以指定也可以动态分配一个随机端口
int startup(u_short *port)
{
 int httpd = 0;
 struct sockaddr_in name;
// 创建一个socket，建立socket连接
 httpd = socket(PF_INET, SOCK_STREAM, 0);
 if (httpd == -1)
  error_die("socket");
 // 填充结构体
 memset(&name, 0, sizeof(name));
 name.sin_family = AF_INET;
 name.sin_port = htons(*port);
 name.sin_addr.s_addr = htonl(INADDR_ANY);

 // 将socket绑定到对应的端口上
 if (bind(httpd, (struct sockaddr *)&name, sizeof(name)) < 0)
  error_die("bind");

 // 如果当前指定的端口是0，则动态随机分配一个端口
 if (*port == 0)  /* if dynamically allocating a port */
 {
  int namelen = sizeof(name);

  // 1.getsockname()可以获得一个与socket相关的地址
        //  1）服务器端可以通过它得到相关客户端地址
        //  2）客户端可以得到当前已连接成功的socket的IP和端口
  // 2.在客户端不进行bind而直接连接服务器时，且客户端需要知道当前使用哪个IP地址
        //   进行通信时比较有用（如多网卡的情况）
  if (getsockname(httpd, (struct sockaddr *)&name, &namelen) == -1)
   error_die("getsockname");
  *port = ntohs(name.sin_port);
 }

 // 开始监听
 if (listen(httpd, 5) < 0)
  error_die("listen");

 // 返回socket id
 return(httpd);
}

/**********************************************************************/
/* Inform the client that the requested web method has not been
 * implemented.
 * Parameter: the client socket */
/**********************************************************************/
void unimplemented(int client)
{
 char buf[1024];

 sprintf(buf, "HTTP/1.0 501 Method Not Implemented\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, SERVER_STRING);
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "Content-Type: text/html\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "<HTML><HEAD><TITLE>Method Not Implemented\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "</TITLE></HEAD>\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "<BODY><P>HTTP request method not supported.\r\n");
 send(client, buf, strlen(buf), 0);
 sprintf(buf, "</BODY></HTML>\r\n");
 send(client, buf, strlen(buf), 0);
}

/**********************************************************************/

int main(void)
{
 int server_sock = -1;
 u_short port = 0;
 int client_sock = -1;
 struct sockaddr_in client_name;
 int client_name_len = sizeof(client_name);
 pthread_t newthread;
 
 // 建立一个监听套接字，在对应的端口建立httpd服务
 server_sock = startup(&port);
 printf("httpd running on port %d\n", port);
// 进入循环，服务器通过调用accept等待客户端的连接，Accept会以阻塞的方式运行，直到
    // 有客户端连接才会返回。连接成功后，服务器启动一个新的线程来处理客户端的请求，处理
    // 完成后，重新等待新的客户端请求。
 while (1)
{
// 返回一个已连接套接字，套接字收到客户端连接请求
  client_sock = accept(server_sock,
                       (struct sockaddr *)&client_name,
                       &client_name_len);
  if (client_sock == -1)
   error_die("accept");
// 派生线程用accept_request函数处理新请求。
 /* accept_request(client_sock); */
 if (pthread_create(&newthread , NULL, accept_request, client_sock) != 0)
   perror("pthread_create");
 }
// 出现意外退出的时候，关闭socket
 close(server_sock);

 return(0);
}
