/*
** Main.cpp
** ETZhangSX
*/

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h> //epoll头文件
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string>
#include <iostream>
#include <sstream>
#include <vector>
#include <pthread.h>
#include <openssl/ssl.h>

#define CHAIN "1_root_bundle.crt"
#define CERTSERVER "2_www.etzhang.xyz.crt"
#define KEYSERVER "3_www.etzhang.xyz.key"

using namespace std;

const int port = 443;
const int buffer_size = 1<<20;
const int method_size = 1<<10;
const int filename_size = 1<<10;
const int common_buffer_size = 1<<10;
const int MAX_EVENTS = 256;
const int TIMEOUT = 500;
const int MAX_CON = 512;

struct client_data{
    char method[method_size];
    char filename[filename_size];
};

struct ssl_data {
    int fd;
    SSL* ssl;
};
//声明epoll_event结构体的变量
struct epoll_event ev, event[MAX_EVENTS];
struct client_data cln_data[MAX_CON];

void setnonblocking(int sock);
void handleError(const string &msg);
void epollHandling(int epfd, int pos);
void requestHandling(int *sock);
void sendError(int *sock);
void t_sendData(int *sock, char *filename);
void sendData(int *sock, char *filename);
void sendHTML(int *sock, char *filename);
void sendJPG(int *sock, char *filename);
void sendICO(int *sock, char *filename);

void ssl_sendData(ssl_data* sd, char *filename);
void ssl_sendHTML(ssl_data* sd, char *filename);
void ssl_sendJPG(ssl_data* sd, char *filename);
void ssl_sendICO(ssl_data* sd, char *filename);
void ssl_sendError(SSL* ssl);

#define CHK_ERR(err, s) if((err) == -1) { perror(s); return -1; }
#define CHK_RV(rv, s) if((rv) != 1) { printf("%s error\n", s); return -1; }
#define CHK_NULL(x, s) if((x) == NULL) { printf("%s error\n", s); return -1; }
//#define CHK_SSL(err, s) if((err) == -1) { ERR_print_errors_fp(stderr);  return -1;}

void sendHelp(FILE *fp, int *sock);

void* handleEvent(void *);

int server_sock;
int client_sock;
    //声明epoll句柄
int epfd;
    //声明事件发生数
int nfds;

vector<int> thread_epoll;

int main() {
    int rv;
    SSL_CTX *ctx = NULL;
    //const SSL_METHOD *method = NULL;
    SSL *ssl = NULL;
    //SSL初始化
    rv = SSL_library_init();
    CHK_RV(rv, "SSL_library_init");

    const SSL_METHOD *method = SSLv23_server_method();
    ctx = SSL_CTX_new(method);
    CHK_NULL(ctx, "SSL_CTX_new");

    SSL_CTX_load_verify_locations(ctx, CHAIN, NULL);
    rv = SSL_CTX_use_certificate_file(ctx, CERTSERVER, SSL_FILETYPE_PEM);
    CHK_RV(rv, "SSL_CTX_use_certicificate_file");
    rv = SSL_CTX_use_PrivateKey_file(ctx, KEYSERVER, SSL_FILETYPE_PEM);
    CHK_RV(rv, "SSL_CTX_use_PrivateKey_file");
    //rv = SSL_CTX_use_certificate_chain_file(ctx, CHAIN);
    //CHK_RV(rv, "SSL_CTX_use_certificate_chain_file");

    rv = SSL_CTX_check_private_key(ctx);
	CHK_RV(rv, "SSL_CTX_check_private_key");
    //声明套接字
    //生成epoll句柄
    epfd = epoll_create(MAX_EVENTS);
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    
    socklen_t client_address_size;
    
    //创建套接字
    server_sock = socket(PF_INET, SOCK_STREAM, 0);
    CHK_ERR(server_sock, "socket");
    // setnonblocking(server_sock);

    //设置相关描述符
    ev.data.fd = server_sock;
    //设置事件类型为 可读 边缘触发
    ev.events = EPOLLIN|EPOLLET;
    //注册epoll事件
    epoll_ctl(epfd, EPOLL_CTL_ADD, server_sock, &ev);

    if (server_sock == -1) {
        handleError("socket error");
    }
    
    //初始化并设置套接字地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(port);
    
    //绑定
    if (bind(server_sock, (struct sockaddr*) &server_addr, sizeof(server_addr)) == -1) {
        handleError("bind error");
    }
    
    //监听
    if (listen(server_sock, 5) == -1) {
        handleError("listen error");
    }

    pthread_t threadid;
    pthread_create (&threadid, NULL, &handleEvent, NULL);

    sleep(1);

    while (true) {
    	client_address_size = sizeof(client_addr);
        client_sock = accept(server_sock, (struct sockaddr*) &client_addr, &client_address_size);
                
        if (client_sock == -1) {
            handleError("accept error");
        }
        // setnonblocking(client_sock);

        char *str = inet_ntoa(client_addr.sin_addr);
        cout << "accept from " << str << endl;

        ssl = SSL_new(ctx);
	    CHK_NULL(ssl, "SSL_new");
	    rv = SSL_set_fd(ssl, client_sock);
	    CHK_RV(rv, "SSL_set_fd");
	    rv = SSL_accept(ssl);
	    CHK_RV(rv, "SSL_accpet");

        // rv = SSL_read(ssl, buf, sizeof(buf) - 1);
	    // CHK_SSL(rv, "SSL_read");
	    // buf[rv] = '\0';
	    // printf("Got %d chars :%s\n", rv, buf);
	    // rv = SSL_write(ssl, "I accept your request", strlen("I accept your request"));
	    // CHK_SSL(rv, "SSL_write");
 
	    // close(accept_sd);
	    // SSL_free(ssl);
	    // SSL_CTX_free(ctx);

        //注册事件描述符
        // ev.data.fd = client_sock;
        ssl_data* sd = new ssl_data();
        sd->fd = client_sock;
        sd->ssl = ssl;
        ev.data.ptr = sd;
        //注册事件的类型
        ev.events = EPOLLIN|EPOLLET;
        //注册事件
        epoll_ctl(thread_epoll[0], EPOLL_CTL_ADD, client_sock, &ev);
    }
    /*
    //等待消息传入
    while (true) {
        //等待epoll事件发生
        nfds = epoll_wait(epfd, event, MAX_EVENTS, TIMEOUT);

        //处理发生事件
        for (int i = 0; i < nfds; i++) {
            
            if (event[i].data.fd == server_sock) {
                
                client_address_size = sizeof(client_addr);
                client_sock = accept(server_sock, (struct sockaddr*) &client_addr, &client_address_size);
                
                if (client_sock == -1) {
                    handleError("accept error");
                }
                // setnonblocking(client_sock);

                char *str = inet_ntoa(client_addr.sin_addr);
                cout << "accept from " << str << endl;

                //注册事件描述符
                ev.data.fd = client_sock;
                //注册事件的类型
                ev.events = EPOLLIN|EPOLLET;
                //注册事件
                epoll_ctl(epfd, EPOLL_CTL_ADD, client_sock, &ev);
            }
            else {
                epollHandling(epfd, i);
            }
        }
        // requestHandling(&client_sock);
    }
    */
    SSL_CTX_free(ctx);
    close(server_sock);
    close(epfd);
    return 0;
}

void* handleEvent(void* obj) {
	int epoll_fd = epoll_create(MAX_EVENTS);
	thread_epoll.push_back(epoll_fd);

	while (true) {
		int event_count = epoll_wait(epoll_fd, event, MAX_EVENTS, TIMEOUT);
		for (int i = 0; i < event_count; i++) {
			epollHandling(epoll_fd, i);
		}
	}
}

void setnonblocking(int sock) {
    int opts;
    opts = fcntl(sock, F_GETFL);
    if (opts < 0) {
        perror("fcntl(sock,GETFL)");
        exit(1);
    }
    opts = opts|O_NONBLOCK;
    if (fcntl(sock, F_SETFL, opts) < 0) {
        perror("fcntl(sock, SETFL, opts)");
        exit(1);
    }
}

//处理epoll事件
void epollHandling(int epfd, int pos) {
    // int client_sock = event[pos].data.fd;
    ssl_data* sd = (ssl_data*) event[pos].data.ptr;
    int client_sock = sd->fd;
    SSL* ssl = sd->ssl;
    char buffer[buffer_size];
    // char method[method_size];
    // char filename[filename_size];

    string t_method;
    string t_filename;
    string t_httpversion;

    if (event[pos].events & EPOLLIN) {
            
        cout << "EPOLLIN" << endl;

        if (client_sock < 0) {
            return;
        }
        
        //读取数据到buffer
        // read(client_sock, buffer, sizeof(buffer) - 1);
        SSL_read(ssl, buffer, sizeof(buffer) - 1);
	    //CHK_SSL(rv, "SSL_read");
        //获取请求头
        string test(buffer);
        stringstream input(test);
        input >> t_method;
        input >> t_filename;
        input >> t_httpversion;

        if (t_httpversion.find("HTTP/") < 0) {
            ssl_sendError(ssl);
            delete sd;
            epoll_ctl(epfd, EPOLL_CTL_DEL, client_sock, NULL);
            close(client_sock);
            SSL_free(ssl);
            return;
        }

        if (t_filename == "/" || t_filename == "/home") {
            t_filename = "./index.html";
        }
        else {
            t_filename = "." + t_filename;
        }

        if (t_method != "GET") {
            ssl_sendError(ssl);
            delete sd;
            epoll_ctl(epfd, EPOLL_CTL_DEL, client_sock, NULL);
            close(client_sock);
            SSL_free(ssl);
            return;
        }

        //判断是否是HTTP请求
        // if (!strstr(buffer, "HTTP/")) {
        //     sendError(&client_sock);
        //     epoll_ctl(epfd, EPOLL_CTL_DEL, client_sock, NULL);
        //     close(client_sock);
        //     return;
        // }
    
        // strcpy(method, strtok(buffer, " /"));
        // strcpy(filename, strtok(NULL, " /"));
    
        // if (0 == strcmp(filename, "HTTP") || 0 == strcmp(filename, "home"))
        //     strcpy(filename, "index.html");

        // if (0 != strcmp(method, "GET")) {
        //     sendError(&client_sock);
        //     epoll_ctl(epfd, EPOLL_CTL_DEL, client_sock, NULL);
        //     close(client_sock);
        //     return;
        // }

        //修改注册事件
        // ev.data.fd = client_sock;
        sd->fd = client_sock;
        sd->ssl = ssl;
        ev.data.ptr = sd;
        ev.events = EPOLLOUT|EPOLLET;
        epoll_ctl(epfd, EPOLL_CTL_MOD, client_sock, &ev);

        //将读取信息保存
        strcpy(cln_data[client_sock].method, t_method.c_str());
        strcpy(cln_data[client_sock].filename, t_filename.c_str());
    }
    else if (event[pos].events & EPOLLOUT) {
        // t_sendData(&client_sock, cln_data[client_sock].filename);
        ssl_sendData((ssl_data*)event[pos].data.ptr, cln_data[client_sock].filename);
        epoll_ctl(epfd, EPOLL_CTL_DEL, client_sock, NULL);
    }
}

//用于原非epoll的简单socket实现版本
//由epoll替代
//处理请求
void requestHandling(int *sock) {
    int client_sock = *sock;
    char buffer[buffer_size];
    char method[method_size];
    char filename[filename_size];
    
    //读取数据到buffer
    read(client_sock, buffer, sizeof(buffer) - 1);

    
    //判断是否是HTTP请求
    if (!strstr(buffer, "HTTP/")) {
        sendError(sock);
        close(client_sock);
        return;
    }
    
    strcpy(method, strtok(buffer, " /"));
    strcpy(filename, strtok(NULL, " /"));
    
    if (0 == strcmp(filename, "HTTP"))
        strcpy(filename, "index.html");

    if (0 != strcmp(method, "GET")) {
        sendError(sock);
        close(client_sock);
        return;
    }
    
    sendData(sock, filename);
}

void ssl_sendData(ssl_data* sd, char *filename) {
    int client_sock = sd->fd;
    SSL* ssl = sd->ssl;
    // char buffer[common_buffer_size];
    string t_filename(filename);
    string type;

    cout << t_filename << endl;

    int pos = t_filename.find('.', 1);

    if (pos < 1) {
        ssl_sendError(ssl);
        close(client_sock);
        SSL_free(ssl);
        delete sd;
        return;
    }

    type = t_filename.substr(pos);
    if (type == ".html") {
        // sendHTML(sock, filename);
        ssl_sendHTML(sd, filename);
    }
    else if (type == ".jpg") {
        // sendJPG(sock, filename);
        ssl_sendJPG(sd, filename);
    }
    else if (type == ".ico") {
        // sendICO(sock, filename);
        ssl_sendICO(sd, filename);
    }
    else {
        ssl_sendError(ssl);
        close(client_sock);
        SSL_free(ssl);
        delete sd;
        return;
    }
}

void t_sendData(int *sock, char *filename) {
    int client_sock = *sock;
    // char buffer[common_buffer_size];
    string t_filename(filename);
    string type;

    cout << t_filename << endl;

    int pos = t_filename.find('.', 1);

    if (pos < 1) {
        sendError(sock);
        close(client_sock);
        return;
    }

    type = t_filename.substr(pos);
    if (type == ".html") {
        sendHTML(sock, filename);
    }
    else if (type == ".jpg") {
        sendJPG(sock, filename);
    }
    else if (type == ".ico") {
        sendICO(sock, filename);
    }
    else {
        sendError(sock);
        close(client_sock);
        return;
    }
}

//发送数据
void sendData(int *sock, char *filename) {
    int client_sock = *sock;
    char buffer[common_buffer_size];
    char type[common_buffer_size];
    printf("%s\n", filename);
    strcpy(buffer, filename);
    strtok(buffer, ".");
    strcpy(type, strtok(NULL, "."));

    // a test of open file
    // string temp(filename);
    // temp = "./" + temp;
    // filename = temp.c_str;
    // strcpy(filename, temp.c_str());

    //多路选择数据类型，多类型可使用switch代替
    if (0 == strcmp(type, "html")) {
        sendHTML(sock, filename);
    }else if (0 == strcmp(type, "jpg")) {
        sendJPG(sock, filename);
    }else if (0 == strcmp(type, "ico")) {
        sendICO(sock, filename);
    }

    else{
        sendError(sock);
        close(client_sock);
        return;
    }
}

//发送页面
void ssl_sendHTML(ssl_data* sd, char *filename) {
    int client_sock = sd->fd;
    SSL* ssl = sd->ssl;
    char buffer[buffer_size];
    FILE *fp;
    
    char status[] = "HTTP/1.1 200 OK\r\n";
    char header[] = "Server: A Simple Web Server\r\nContent-Type: text/html\r\n\r\n";
    
    SSL_write(ssl, status, strlen(status));
    SSL_write(ssl, header, strlen(header));
    // write(client_sock, status, strlen(status));
    // write(client_sock, header, strlen(header));
    
    fp = fopen(filename, "r");
    if (!fp) {
        ssl_sendError(ssl);
        close(client_sock);
        SSL_free(ssl);
        delete sd;
        handleError("open file failed");
        return;
    }
    
    // fgets(buffer, sizeof(buffer), fp);
    while(!feof(fp)) {
        fgets(buffer, sizeof(buffer), fp);
        // write(client_sock, buffer, strlen(buffer));
        SSL_write(ssl, buffer, strlen(buffer));
    }
    
    fclose(fp);
    close(client_sock);
    SSL_free(ssl);
    delete sd;
}

void sendHTML(int *sock, char *filename) {
    int client_sock = *sock;
    char buffer[buffer_size];
    FILE *fp;
    
    char status[] = "HTTP/1.1 200 OK\r\n";
    char header[] = "Server: A Simple Web Server\r\nContent-Type: text/html\r\n\r\n";
    
    write(client_sock, status, strlen(status));
    write(client_sock, header, strlen(header));
    
    fp = fopen(filename, "r");
    if (!fp) {
        sendError(sock);
        close(client_sock);
        handleError("open file failed");
        return;
    }
    
    // fgets(buffer, sizeof(buffer), fp);
    while(!feof(fp)) {
        fgets(buffer, sizeof(buffer), fp);
        write(client_sock, buffer, strlen(buffer));
    }
    
    fclose(fp);
    close(client_sock);
}

void ssl_sendJPG(ssl_data* sd, char *filename) {
    int client_sock = sd->fd;
    SSL* ssl = sd->ssl;
    // char buffer[buffer_size];
    FILE *fp;
    // FILE *fw;
    fp = fopen(filename, "rb");

    fseek(fp, 0L, SEEK_END);
    int len = ftell(fp);

    string status = "HTTP/1.1 200 OK\r\n";
    
    string header = "Server: A Simple Web Server\r\nContent-Type: image/jpeg\r\n";
    header += "Content-Range: bytes ";
    header += to_string(0);
    header += "-";
    header += to_string(len - 1);
    header += "/";
    header += to_string(len);
    header += "\r\n";
    header += "Content-Length: ";
    header += to_string(len);
    header += "\r\n\r\n";
    SSL_write(ssl, status.c_str(), status.length());
    SSL_write(ssl, header.c_str(), header.length());
    

    if (NULL == fp) {
        ssl_sendError(ssl);
        close(client_sock);
        handleError("open file failed");
        return;
    }


    printf("Sending img\n");
    // fw = fdopen(client_sock, "wb");

    fseek(fp, 0L, SEEK_SET);

    //循环读写，确保文件读完
    sendHelp(fp, &client_sock);

    SSL_free(ssl);
    delete sd;
    // while (!feof(fp)) {
    //     fread(buffer, sizeof(char), sizeof(buffer), fp);
    //     fwrite(buffer, sizeof(char), sizeof(buffer), fw);
    // }
    
    // printf("Finish sending\n");

    // fclose(fw);
    // fclose(fp);
    // close(client_sock);
}

void sendJPG(int *sock, char *filename) {
    int client_sock = *sock;
    // char buffer[buffer_size];
    FILE *fp;
    // FILE *fw;
    fp = fopen(filename, "rb");

    fseek(fp, 0L, SEEK_END);
    int len = ftell(fp);

    string status = "HTTP/1.1 200 OK\r\n";
    
    string header = "Server: A Simple Web Server\r\nContent-Type: image/jpeg\r\n";
    header += "Content-Range: bytes ";
    header += to_string(0);
    header += "-";
    header += to_string(len - 1);
    header += "/";
    header += to_string(len);
    header += "\r\n";
    header += "Content-Length: ";
    header += to_string(len);
    header += "\r\n\r\n";
    write(client_sock, status.c_str(), status.length());
    write(client_sock, header.c_str(), header.length());
    

    if (NULL == fp) {
        sendError(sock);
        close(client_sock);
        handleError("open file failed");
        return;
    }


    printf("Sending img\n");
    // fw = fdopen(client_sock, "wb");

    fseek(fp, 0L, SEEK_SET);

    //循环读写，确保文件读完
    sendHelp(fp, sock);
    // while (!feof(fp)) {
    //     fread(buffer, sizeof(char), sizeof(buffer), fp);
    //     fwrite(buffer, sizeof(char), sizeof(buffer), fw);
    // }
    
    // printf("Finish sending\n");

    // fclose(fw);
    // fclose(fp);
    // close(client_sock);
}

void sendHelp(FILE *fp, int *sock) {
    int client_sock = *sock;
    FILE *fw;

    char buffer[buffer_size];

    fw = fdopen(client_sock, "wb");

    while (!feof(fp)) {
        fread(buffer, sizeof(char), sizeof(buffer), fp);
        fwrite(buffer, sizeof(char), sizeof(buffer), fw);
    }

    cout << "Finish sending\n";
    fclose(fw);
    fclose(fp);
    close(client_sock);
}

void ssl_sendICO(ssl_data* sd, char *filename) {
    int client_sock = sd->fd;
    SSL* ssl = sd->ssl;
    char buffer[buffer_size];
    FILE *fp;
    FILE *fw;
    fp = fopen(filename, "rb");

    fseek(fp, 0L, SEEK_END);
    int len = ftell(fp);

    string status = "HTTP/1.1 200 OK\r\n";
    
    string header = "Server: A Simple Web Server\r\nContent-Type: text/html\r\n";
    header += "Content-Range: bytes ";
    header += to_string(0);
    header += "-";
    header += to_string(len - 1);
    header += "/";
    header += to_string(len);
    header += "\r\n";
    header += "Content-Length: ";
    header += to_string(len);
    header += "\r\n\r\n";
    // write(client_sock, status.c_str(), status.length());
    // write(client_sock, header.c_str(), header.length());
    SSL_write(ssl, status.c_str(), status.length());
    SSL_write(ssl, header.c_str(), header.length());
    
    if (NULL == fp) {
        ssl_sendError(ssl);
        close(client_sock);
        handleError("open file failed");
        return;
    }

    printf("Sending favicon.ico\n");
    fw = fdopen(client_sock, "wb");

    fseek(fp, 0L, SEEK_SET);

    //循环读写，确保文件读完
    while (!feof(fp)) {
        fread(buffer, sizeof(char), sizeof(buffer), fp);
        fwrite(buffer, sizeof(char), sizeof(buffer), fw);
    }
    
    printf("Finish sending\n");

    fclose(fw);
    fclose(fp);
    close(client_sock);
    SSL_free(ssl);
    delete sd;
}

void sendICO(int *sock, char *filename) {
    int client_sock = *sock;
    char buffer[buffer_size];
    FILE *fp;
    FILE *fw;
    fp = fopen(filename, "rb");

    fseek(fp, 0L, SEEK_END);
    int len = ftell(fp);

    string status = "HTTP/1.1 200 OK\r\n";
    
    string header = "Server: A Simple Web Server\r\nContent-Type: text/html\r\n";
    header += "Content-Range: bytes ";
    header += to_string(0);
    header += "-";
    header += to_string(len - 1);
    header += "/";
    header += to_string(len);
    header += "\r\n";
    header += "Content-Length: ";
    header += to_string(len);
    header += "\r\n\r\n";
    write(client_sock, status.c_str(), status.length());
    write(client_sock, header.c_str(), header.length());
    

    if (NULL == fp) {
        sendError(sock);
        close(client_sock);
        handleError("open file failed");
        return;
    }


    printf("Sending favicon.ico\n");
    fw = fdopen(client_sock, "wb");

    fseek(fp, 0L, SEEK_SET);

    //循环读写，确保文件读完
    while (!feof(fp)) {
        fread(buffer, sizeof(char), sizeof(buffer), fp);
        fwrite(buffer, sizeof(char), sizeof(buffer), fw);
    }
    
    printf("Finish sending\n");

    fclose(fw);
    fclose(fp);
    close(client_sock);
}

void handleError(const string &msg) {
    cout << msg;
    exit(1);
}

void ssl_sendError(SSL* ssl) {
    
    char status[] = "HTTP/1.1 400 Bad Request\r\n";
    char header[] = "Server: A Simple Web Server\r\nContent-Type: text/html\r\n\r\n";
    char body[] = "<html><head><title>Bad Request</title></head><body><p>400 Bad Request</p></body></html>";
    
    SSL_write(ssl, status, strlen(status));
    SSL_write(ssl, header, strlen(header));
    SSL_write(ssl, body, strlen(body));
}

void sendError(int *sock) {
    int client_sock = *sock;
    
    char status[] = "HTTP/1.1 400 Bad Request\r\n";
    char header[] = "Server: A Simple Web Server\r\nContent-Type: text/html\r\n\r\n";
    char body[] = "<html><head><title>Bad Request</title></head><body><p>400 Bad Request</p></body></html>";
    
    write(client_sock, status, strlen(status));
    write(client_sock, header, strlen(header));
    write(client_sock, body, strlen(body));
}